# InfraFlow — Scanner Configuration & Execution Standards

## 1. Overview

InfraFlow orchestrates four primary static analysis and security tools:
- **Trivy**: Infrastructure-as-Code (IaC) misconfiguration and compliance scanner.
- **TFLint**: Terraform-specific static code analysis and linting engine.
- **Zizmor**: GitHub Actions workflow and CI/CD supply chain security auditor.
- **Conftest (OPA)**: Declarative Policy-as-Code engine utilizing Rego rulesets.

This specification details the standardized configuration files, CLI invocations, severity thresholds, and reporting formats across local workstations and remote CI/CD runners.

---

## 2. Trivy Configuration & Execution

### 2.1 Tool Specifications
- **Binary**: `trivy` (Aqua Security)
- **Minimum Version**: `0.76.2`
- **Scan Mode**: `config` (IaC static analysis)

### 2.2 Reusable Invocation Standard
```bash
trivy config \
  --severity HIGH,CRITICAL \
  --exit-code 1 \
  --format table \
  --output trivy-summary.txt \
  "${TARGET_DIRECTORY}"
```

To simultaneously emit machine-readable SARIF for GitHub Security tab integration:
```bash
trivy config \
  --severity HIGH,CRITICAL \
  --format sarif \
  --output trivy-results.sarif \
  "${TARGET_DIRECTORY}"
```

### 2.3 Quality Gate Rules
- Any finding of severity **CRITICAL** or **HIGH** yields an immediate non-zero exit code (`1`), blocking CI.
- Findings of severity **MEDIUM** or **LOW** are surfaced in the job step summary for developer visibility but do not break builds unless configured in strict mode.

---

## 3. TFLint Configuration & Execution

### 3.1 Configuration File (`.tflint.hcl`)
InfraFlow maintains a standardized `.tflint.hcl` at the repository root:

```hcl
config {
  call_module_type = "local"
  force            = false
}

# --- Core Terraform Standard Rules ---
rule "terraform_deprecated_interpolation" {
  enabled = true
}

rule "terraform_deprecated_index" {
  enabled = true
}

rule "terraform_unused_declarations" {
  enabled = true
}

rule "terraform_comment_syntax" {
  enabled = true
}

rule "terraform_naming_conventions" {
  enabled = true
}

rule "terraform_standard_module_structure" {
  enabled = true
}

rule "terraform_typed_variables" {
  enabled = true
}

rule "terraform_module_version" {
  enabled = true
}

# --- Future Cloud Rulesets (Activated per Provider Adapter) ---
# plugin "aws" {
#   enabled = true
#   version = "0.38.0"
#   source  = "github.com/terraform-linters/tflint-ruleset-aws"
# }
# plugin "azurerm" {
#   enabled = true
#   version = "0.27.0"
#   source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
# }
# plugin "google" {
#   enabled = true
#   version = "0.30.0"
#   source  = "github.com/terraform-linters/tflint-ruleset-google"
# }
```

### 3.2 Invocation Standard
```bash
tflint --chdir="${TARGET_DIRECTORY}" --minimum-failure-severity=warning
```

### 3.3 Plugin Configuration & Provider Coverage Limits
> [!IMPORTANT]
> **Deterministic Provider Scope**:
> In the current baseline (Milestone G03), TFLint is configured exclusively with **core Terraform built-in rules** (variable typing, naming, documentation, syntax deprecations, and module versioning).
> Provider-specific plugins (`tflint-ruleset-aws`, `tflint-ruleset-azurerm`, `tflint-ruleset-google`) are **not enabled** in the offline baseline to preserve the $0 budget, zero-credential, and offline execution requirements. Cloud-specific linting coverage is therefore not claimed for TFLint in G03 and is scheduled for the Tier 2 Cloud Adapters milestone.

---

## 4. Zizmor Configuration & Execution

### 4.1 Tool Specifications
- **Binary**: `zizmor`
- **Minimum Version**: `1.32.0`
- **Target**: `.github/workflows`

### 4.2 Invocation Standard
```bash
zizmor -c .zizmor.yml --min-severity medium --persona regular .github/workflows
```

### 4.3 Audited Invariants & Exception Analysis
- **Unpinned Actions (`unpinned-uses`)**: Enforces 40-character commit SHAs for external actions.
- **Dangerous Permissions (`artipacked`, etc.)**: Flags `permissions: write-all` or unconstrained tokens.
- **Expression Injection (`template-injection`)**: Detects unsafe `${{ github.event... }}` expansions inside inline bash steps.
- **Insecure Triggers**: Flags `pull_request_target` usage when executing untrusted checkout.

#### Audit Finding & Justification: `self-repository`
During security auditing (Milestone G03.1), Zizmor reported a `Low` (Help) finding for `ci.yml`:
- **Finding ID**: `self-repository`
- **Location**: `.github/workflows/ci.yml` (`uses: ./.github/workflows/...`)
- **Recommendation**: Replace `./.github/workflows/...` with GitHub's dedicated self-repository syntax `$/...`.
- **Parser Incompatibility**: The workflow linter `actionlint` v1.7.7 strictly rejects `uses: $/.github/workflows/...` as an invalid workflow call format. Adopting `$/...` breaks actionlint and standard GitHub runner parsers.
- **Narrow Rule-Level Scoping**: `.zizmor.yml` restricts the suppression exclusively to `self-repository` for `ci.yml`. It does **not** blanket-ignore `ci.yml`; all critical, high, and medium supply chain security rules remain active and enforced across all workflows.
- **Compensating Control**: The referenced workflows execute in an ephemeral runner under read-only token permissions (`contents: read`) within `$GITHUB_WORKSPACE`.
- **Review Condition**: Re-evaluate when actionlint adds official support for the `$/...` self-repository syntax.

---

## 5. Conftest / OPA Policy Configuration & Execution

### 5.1 Tool Specifications
- **Binary**: `conftest` (Open Policy Agent)
- **Minimum Version**: `0.71.1`
- **Rego Syntax**: Rego v1 (`--rego-version v1`)

### 5.2 Invocation Standards

#### Static HCL Code Scanning (Pre-Plan):
```bash
conftest test \
  --policy policies/ \
  --parser hcl2 \
  "${TARGET_DIRECTORY}/*.tf"
```

#### Terraform Plan JSON Scanning (Post-Plan):
```bash
conftest test \
  --policy policies/ \
  --namespace terraform.plan \
  tfplan.json
```

#### Unit Testing Rego Policies:
```bash
conftest verify --policy policies/
```

---

## 6. Local Developer Quickstart

To run the complete DevSecOps security suite locally before pushing code:

```bash
# 1. Run TFLint
tflint --chdir=examples/cloud-free-module

# 2. Run Trivy IaC Scan
trivy config --severity HIGH,CRITICAL examples/cloud-free-module

# 3. Run Zizmor Workflow Audit
zizmor --min-severity medium .github/workflows

# 4. Verify Rego Policies & Test Code
conftest verify --policy policies
conftest test --policy policies examples/cloud-free-module/*.tf

# 5. Run InfraFlow Complete Validation Harness
./scripts/validate-local.sh
```
