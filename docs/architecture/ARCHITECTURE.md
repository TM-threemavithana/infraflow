# InfraFlow — System Architecture & Workflow Design

## 1. System Vision & Architecture

**InfraFlow** is an enterprise-grade, reusable infrastructure delivery platform designed to provide a unified, secure CI/CD core across distributed engineering teams and multi-cloud environments.

Rather than duplicating GitHub Actions YAML pipelines across dozens of repositories, InfraFlow separates concerns into a **Two-Tier Architecture**:

1. **Tier 1 — Reusable Provider-Neutral CI/CD Core (`reusable-tf-validate.yml`)**:
   - Manages source checkout, toolchain installation, syntax linting, static validation, unit testing, and status reporting.
   - Operates with zero cloud credentials, zero cloud dependencies, and minimum permissions (`contents: read`).
   - Fast, deterministic, and identical across local developer workstations and remote CI runners.

2. **Tier 2 — Modular Cloud Adapters (Future AWS, Azure, GCP Extensions)**:
   - Encapsulates cloud-specific OIDC authentication (AWS AssumeRoleWithWebIdentity, Azure Federated Credentials, GCP Workload Identity Federation).
   - Manages remote state backends (S3/DynamoDB, Azure Blob, GCS) and state locking.
   - Orchestrates speculative planning (`terraform plan`) and controlled approvals/applies.
   - Plugs into the Tier 1 core without modifying provider-neutral logic.

---

## 2. Architecture Diagrams

### 2.1 Multi-Tier Platform Topology

```mermaid
flowchart TD
    subgraph Consumers["Consuming Repositories"]
        R1["Repo A: Network Core\n(.github/workflows/ci.yml)"]
        R2["Repo B: App Infrastructure\n(.github/workflows/ci.yml)"]
        R3["Repo C: Data Platform\n(.github/workflows/ci.yml)"]
    end

    subgraph InfraFlowCore["InfraFlow Platform — Tier 1 (Provider-Neutral Core & DevSecOps Gates)"]
        direction TB
        InputGuard["Input Sanitization & Security Guard"]
        Toolchain["Terraform Toolchain Setup (SHA Pinned)"]
        FmtStep["terraform fmt -check -diff -recursive"]
        InitStep["terraform init -backend=false"]
        ValStep["terraform validate"]
        TestStep["terraform test (Native .tftest.hcl)"]

        subgraph DevSecOps["DevSecOps Security Pipeline (reusable-tf-security.yml)"]
            TFLint["TFLint (Static Analysis & Naming)"]
            Zizmor["Zizmor (Workflow & Supply Chain Security)"]
            Trivy["Trivy (IaC Misconfiguration Scanner)"]
            Conftest["Conftest / OPA (Enterprise Rego Policy Gate)"]
        end

        Summary["Structured Status & Summary Emission"]

        InputGuard --> Toolchain
        Toolchain --> FmtStep
        FmtStep --> InitStep
        InitStep --> ValStep
        ValStep --> TestStep
        TestStep --> Summary

        InputGuard --> TFLint
        InputGuard --> Zizmor
        TFLint --> Trivy
        Zizmor --> Trivy
        Trivy --> Conftest
        Conftest --> Summary
    end

    subgraph Tier2Adapters["Future Tier 2 Adapters (Milestone G03+)"]
        direction TB
        AWS["AWS Adapter\n(OIDC + S3/DynamoDB Backend)"]
        Azure["Azure Adapter\n(OIDC + Blob Storage Backend)"]
        GCP["GCP Adapter\n(OIDC + GCS Backend)"]
    end

    subgraph Targets["Target Infrastructure (Read-Only Planning / Applies)"]
        AWSEnv["AWS Accounts"]
        AzureEnv["Azure Subscriptions"]
        GCPEnv["GCP Projects"]
    end

    R1 -->|"workflow_call (PR Check)"| InputGuard
    R2 -->|"workflow_call (PR Check)"| InputGuard
    R3 -->|"workflow_call (PR Check)"| InputGuard

    Summary -.->|"On Main Merge (Deploy)"| AWS
    Summary -.->|"On Main Merge (Deploy)"| Azure
    Summary -.->|"On Main Merge (Deploy)"| GCP

    AWS -.-> AWSEnv
    Azure -.-> AzureEnv
    GCP -.-> GCPEnv
```

---

### 2.2 Reusable Core Execution Pipeline

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / PR Author
    participant GH as Caller Repository (GitHub)
    participant Core as InfraFlow Core (reusable-tf-validate.yml)
    participant Runner as GitHub-Hosted Runner (ubuntu-latest)
    participant TF as Terraform CLI

    Dev->>GH: Open Pull Request
    GH->>Core: Call reusable-tf-validate.yml (ref: @v1)
    Note over Core: Minimal Token: permissions: contents: read
    Core->>Runner: Initialize Job with Inputs
    Runner->>Runner: Guard: Validate working-directory & semver
    alt Invalid Input or Path Traversal
        Runner-->>GH: Reject execution immediately (Exit 1)
    end
    Runner->>Runner: actions/checkout (SHA-pinned)
    Runner->>Runner: hashicorp/setup-terraform (SHA-pinned, wrapper: false)
    opt enable-fmt-check == true
        Runner->>TF: terraform fmt -check -diff -recursive
        TF-->>Runner: Exit code (0 = Clean, 1 = Drift)
    end
    Runner->>TF: terraform init -backend=false
    TF-->>Runner: Providers & lockfile validated locally
    opt enable-validate == true
        Runner->>TF: terraform validate
        TF-->>Runner: Validation Status
    end
    opt enable-test == true
        Runner->>TF: terraform test -verbose
        TF-->>Runner: Test execution results
    end
    Runner-->>Core: Aggregate Outputs (fmt-status, validate-status, test-status)
    Core-->>GH: Job Completed / PR Status Check Emitted
```

---

## 3. Workflow Specification: `reusable-tf-validate.yml`

### 3.1 Inputs Schema

| Input Name | Type | Required | Default | Description & Validation Constraint |
|---|---|---|---|---|
| `terraform-version` | `string` | No | `'1.10.4'` | SemVer string of Terraform binary (e.g., `1.10.4`, `1.11.0`). Validated against `^[0-9]+\.[0-9]+\.[0-9]+$` and enforced `>= 1.6.0`. |
| `working-directory` | `string` | No | `'.'` | Relative path to directory containing Terraform configuration. Traversal (`..`), absolute paths, and workspace escape are blocked. |
| `enable-fmt-check` | `boolean` | No | `true` | When true, enforces canonical styling via `terraform fmt -check`. |
| `enable-validate` | `boolean` | No | `true` | When true, executes `terraform validate` after backend-free initialization. |
| `enable-test` | `boolean` | No | `true` | When true, executes native tests using `terraform test`. |
| `test-var-file` | `string` | No | `''` | Optional path to a `.tfvars` file for `terraform test -var-file`. Validated against path traversal. |

### 3.2 Outputs Schema

| Output Name | Type | Description |
|---|---|---|
| `fmt-status` | `string` | Status of formatting check: `success`, `failure`, or `skipped`. |
| `validate-status` | `string` | Status of validation step: `success`, `failure`, or `skipped`. |
| `test-status` | `string` | Status of native test suite: `success`, `failure`, or `skipped`. |
| `summary` | `string` | Human-readable execution summary with step outcomes. |

### 3.3 Permissions Contract

The workflow operates under explicit least-privilege permissions:
```yaml
permissions:
  contents: read
  pull-requests: none
  id-token: none
  issues: none
  packages: none
```
This guarantees that caller PRs from forks or internal branches cannot modify repository contents, create releases, or request OIDC identity tokens during Tier 1 validation.

---

## 4. Reusable Security Specification: `reusable-tf-security.yml`

Introduced in **Milestone G03**, this reusable workflow provides dedicated DevSecOps quality gates.

### 4.1 Inputs Schema

| Input Name | Type | Required | Default | Description & Constraint |
|---|---|---|---|---|
| `terraform-version` | `string` | No | `'1.10.4'` | Version of Terraform to initialize for HCL parsing. Must be `>= 1.6.0`. |
| `working-directory` | `string` | No | `'.'` | Directory containing Terraform configuration to scan. |
| `severity-threshold` | `string` | No | `'HIGH,CRITICAL'` | Severities that trigger failure. |
| `enable-tflint` | `boolean` | No | `true` | Executes TFLint static analysis. |
| `enable-trivy` | `boolean` | No | `true` | Executes Trivy IaC misconfiguration scanning. |
| `enable-conftest` | `boolean` | No | `true` | Evaluates Rego policies via Conftest. |
| `enable-zizmor` | `boolean` | No | `false` | Executes Zizmor on `.github/workflows` (if present). |
| `policy-directory` | `string` | No | `'policies'` | Path to policy directory containing Rego files. |

### 4.2 Outputs Schema

| Output Name | Type | Description |
|---|---|---|
| `tflint-status` | `string` | Outcome of TFLint: `success`, `failure`, or `skipped`. |
| `trivy-status` | `string` | Outcome of Trivy: `success`, `failure`, or `skipped`. |
| `conftest-status` | `string` | Outcome of Conftest: `success`, `failure`, or `skipped`. |
| `zizmor-status` | `string` | Outcome of Zizmor: `success`, `failure`, or `skipped`. |
| `security-summary` | `string` | Formatted summary of all security findings. |

---

## 5. Reusable Planning & Approval Specification: `reusable-tf-plan.yml`

Introduced in **Milestone G04**, this reusable workflow provides speculative planning, change analysis, OPA plan evaluation, cryptographic attestation, and protected environment gating.

### 5.1 Inputs Schema

| Input Name | Type | Required | Default | Description & Constraint |
|---|---|---|---|---|
| `terraform-version` | `string` | No | `'1.10.4'` | Version of Terraform to execute. Must be `>= 1.6.0`. |
| `working-directory` | `string` | No | `'.'` | Directory containing Terraform configuration to plan. |
| `var-file` | `string` | No | `''` | Optional relative path to `.tfvars` file. |
| `environment` | `string` | No | `'production-approval'` | Target GitHub Environment name for protected approval gate. |
| `enable-policy-evaluation` | `boolean` | No | `true` | Evaluates Conftest / OPA policies against plan JSON. |
| `policy-directory` | `string` | No | `'policies'` | Path to enterprise Rego policies root. |
| `enable-trivy` | `boolean` | No | `true` | Executes Trivy IaC static scan. |
| `severity-threshold` | `string` | No | `'HIGH,CRITICAL'` | Severities triggering hard scan failure. |
| `fail-on-destructive` | `boolean` | No | `false` | When true, fails plan generation if deletions or replacements occur. |
| `upload-plan-attestation` | `boolean` | No | `true` | Uploads sanitized summary and attestation manifest. |

### 5.2 Outputs Schema

| Output Name | Type | Description |
|---|---|---|
| `plan-status` | `string` | Speculative plan generation outcome (`success`, `failure`, `skipped`). |
| `analysis-status` | `string` | Change classification outcome (`success`, `failure`, `skipped`). |
| `security-status` | `string` | Aggregated security scan outcome (`success`, `failure`, `skipped`). |
| `approval-status` | `string` | Protected environment approval gate status. |
| `has-changes` | `string` | String boolean indicating whether modifying changes are planned. |
| `has-destructive-changes` | `string` | String boolean indicating whether deletions/replacements are planned. |
| `total-changes` | `string` | Total count of modifying resource changes. |

---

## 6. Input Sanitization & Security Guard

To prevent shell injection and path traversal, every invocation evaluates inputs inside an isolated POSIX bash guard before Terraform runs:

```bash
# Security Rule 1: No direct interpolation in bash scripts
# Inputs are mapped to environment variables:
# INPUT_WORKING_DIR="$1"
# INPUT_TF_VERSION="$2"

# Security Rule 2: Path Traversal Check
if [[ "${INPUT_WORKING_DIR}" =~ \.\. ]]; then
  echo "::error::Security Violation: Working directory path cannot contain '..' traversal sequences."
  exit 1
fi

# Security Rule 3: Character Allowlist
if [[ ! "${INPUT_WORKING_DIR}" =~ ^[a-zA-Z0-9_./-]+$ ]]; then
  echo "::error::Security Violation: Working directory contains forbidden characters."
  exit 1
fi

# Security Rule 4: SemVer Format Verification
if [[ ! "${INPUT_TF_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "::error::Security Violation: Terraform version must be valid semantic version (e.g., 1.10.4)."
  exit 1
fi
```

---

## 7. Versioning & Consumer Release Strategy

Reusable workflows in GitHub Actions follow an immutable release strategy:

1. **Semantic Version Tags (`vX.Y.Z`)**:
   Every production release is tagged with a full semantic tag (e.g. `v1.0.0`, `v1.1.0`).
2. **Major Version Rolling Tag (`v1`)**:
   A floating major version tag (`v1`) is updated upon backward-compatible releases, allowing consumers to receive security fixes automatically.
3. **Commit SHA Referencing (`@<40-char-sha>`)**:
   High-security consumer repositories with strict compliance requirements can pin to the exact commit SHA for zero-drift immutability:
   ```yaml
   uses: my-org/infraflow/.github/workflows/reusable-tf-validate.yml@11bd71901bbe5b1630ceea73d27597364c9af683
   ```
4. **Breaking Changes**:
   Any backward-incompatible input or output changes increment the major version (`v2.0.0`), leaving `v1` pipelines completely unaffected.
