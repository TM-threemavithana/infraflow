# InfraFlow Unified Platform CLI — Developer & Operations Guide

Welcome to the **InfraFlow Unified CLI (`infraflow`)** developer guide. This guide covers local installation, environment readiness diagnostics, consumer repository validation, continuous drift detection, and fleet upgrade operations.

---

## 1. Installation & Environment Setup

InfraFlow adheres to modern Python packaging standards (PEP 517 / PEP 621) via `pyproject.toml`. It provides an executable console entry point (`infraflow`) that operates seamlessly across Linux, WSL2 (Ubuntu), macOS, and Windows 11.

### 1.1 Recommended Installation: Editable Development Mode

For platform engineers and active contributors, editable installation links directly to the local source tree without copying files:

```bash
# Optional: create and activate an isolated virtual environment
python3 -m venv .venv
source .venv/bin/activate       # Linux / macOS / WSL2
# On Windows PowerShell: .\.venv\Scripts\Activate.ps1

# Install InfraFlow in editable development mode
pip install -e .

# Verify the console entrypoint is available in your PATH
which infraflow                 # Linux/WSL: outputs /path/to/.venv/bin/infraflow
infraflow --version
```

### 1.2 Standard Installation

To install InfraFlow as a standard package:

```bash
pip install .

# Test invocation
infraflow --version
```

### 1.3 Windows 11 Native Installation

On native Windows 11 (PowerShell or Command Prompt):
```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install in editable mode
pip install -e .

# Pip automatically compiles/generates the launcher binary:
# .\.venv\Scripts\infraflow.exe
infraflow --version
```

### 1.4 Zero-Install Standalone Execution (Backwards-Compatible)

If you prefer not to install the package into your Python environment, you can run the direct wrapper script or invoke the module directly:

```bash
# Option A: Direct script invocation
./scripts/infraflow-cli.py --version

# Option B: Python module invocation
python3 -m infraflow.cli --version
```

### 1.5 Clean Uninstallation

To remove InfraFlow completely:
```bash
pip uninstall -y infraflow
```

---

## 2. Global Flags & Usage Patterns

All `infraflow` commands support standardized global flags:

| Flag | Description |
|---|---|
| `-V, --version` | Display platform version, build metadata, and canonical repository ref. |
| `--json` | Emit structured, machine-readable JSON to stdout (ideal for CI/CD scripting). |
| `-v, --verbose` | Enable trace logs, full file locations, and detailed failure diagnostics. |
| `--no-color` | Disable ANSI terminal styling (automatically respected if `NO_COLOR` is set). |

---

## 3. Command Reference

### 2.1 `infraflow doctor` — Environment Diagnostics

Performs a comprehensive, **purely non-destructive** assessment of your local system across 12 critical platform dimensions:

```bash
# Run standard diagnostic check
infraflow doctor

# Output diagnostic matrix as JSON
infraflow doctor --json

# Strict mode: fail with non-zero exit code if any warnings are detected
infraflow doctor --strict
```

#### Diagnostic Evaluation Matrix:
1. **Python Runtime**: Verifies Python `>= 3.10`.
2. **Terraform CLI**: Verifies HashiCorp Terraform `>= 1.6.0`.
3. **Git CLI**: Verifies Git `>= 2.0`.
4. **TFLint**: Verifies TFLint IaC linter availability.
5. **Trivy**: Verifies Trivy vulnerability and misconfiguration scanner.
6. **Conftest (OPA)**: Verifies Conftest Open Policy Agent runtime.
7. **Actionlint**: Verifies GitHub Actions workflow linter.
8. **Zizmor**: Verifies workflow security static analysis engine.
9. **Platform Directory Hierarchy**: Verifies `.github/workflows`, `policies`, `scripts`, `docs`, `config`, `tests`.
10. **Core Rego Policies**: Verifies AWS, Azure, GCP, Common, and Governance policy files.
11. **Python Dependencies**: Verifies PyYAML and cryptography libraries.
12. **Git Workspace State**: Verifies clean working tree and records branch/commit SHA.

---

### 2.2 `infraflow validate` — Governance & Policy Engine

Validates consumer onboarding contracts, fleet manifests, or evaluates OPA policies with intelligent error enhancement.

#### Validating a Consumer Repository Configuration:
```bash
# Validate local consumer repo
infraflow validate --config /path/to/consumer/infraflow.config.yaml

# Export normalized governance JSON payload for OPA evaluation
infraflow validate --config infraflow.config.yaml --export-governance-payload /tmp/gov.json
```

#### Validating a Fleet Manifest:
```bash
# Verify fleet manifest schema and commit SHA pinning
infraflow validate -m config/fleet-manifest.yaml
```

#### Evaluating OPA / Conftest Policies with Intelligent Error Enrichment:
```bash
# Test a Terraform configuration against AWS S3 security policy
infraflow validate \
  --policy-file policies/aws/s3.rego \
  --input-file fixtures/security/policies/invalid-aws/main.tf \
  --namespace aws.s3
```

When a policy failure occurs, `infraflow validate` automatically:
- Identifies the violated **Policy ID** (e.g. `AWS-SEC-S3-ACL-001`, `AZURE-SEC-TLS-001`).
- Classifies severity (`CRITICAL`, `HIGH`, `MEDIUM`).
- Identifies the target resource name and line number in the source file.
- Provides actionable **Remediation Advice** to fix the issue immediately.

---

### 2.3 `infraflow drift` — Continuous State & Speculative Drift Detection

Simulates infrastructure drift between expected and observed state snapshots without making live cloud API calls ($0.00 cloud spend guarantee).

```bash
# Run drift detection comparison
infraflow drift \
  --expected fixtures/drift/aws/clean/expected.json \
  --observed fixtures/drift/aws/clean/observed.json

# Enforce zero-drift gate in CI/CD pipeline (fails closed if drift detected)
infraflow drift \
  --expected expected.json \
  --observed observed.json \
  --enforce-zero-drift

# Export reports and emit structured telemetry
infraflow drift \
  --expected expected.json \
  --observed observed.json \
  --output-json reports/drift.json \
  --output-markdown reports/drift.md \
  --emit-telemetry \
  --telemetry-output reports/telemetry.jsonl
```

---

### 2.4 `infraflow upgrade` — Fleet Upgrade Campaigns

Plans, applies, or rolls back platform reusable workflow upgrades across registered consumer repositories.

```bash
# Generate upgrade dry-run plan across the fleet
infraflow upgrade -m config/fleet-manifest.yaml --plan

# Plan upgrade for a specific target consumer
infraflow upgrade -m config/fleet-manifest.yaml --plan --consumer consumer-networking

# Apply upgrade to Canary stage consumers
infraflow upgrade -m config/fleet-manifest.yaml --apply --stage canary

# Emergency rollback: restore consumers to known-good baseline SHA
infraflow upgrade -m config/fleet-manifest.yaml --rollback
```

---

## 3. Exit Codes & CI/CD Integration

| Exit Code | Meaning | Typical Scenario |
|---|---|---|
| `0` | **Success** | All diagnostics healthy; validation clean; zero drift detected; plan succeeded. |
| `1` | **Operational / Validation Failure** | Policy violation detected; drift gate tripped; doctor failure. |
| `2` | **Security Invariant Breach** | Symbolic link detected; path traversal attempt; tampering error. |

### Example GitHub Actions CI Step:
```yaml
- name: Run InfraFlow Pre-Flight Doctor
  run: |
    python3 scripts/infraflow-cli.py doctor --strict --json > doctor-report.json

- name: Validate Consumer Governance Contract
  run: |
    python3 scripts/infraflow-cli.py validate --config infraflow.config.yaml
```

---

## 4. Security & Safety Invariants

- **$0.00 Cloud Spending:** All commands execute locally and offline without contacting cloud APIs.
- **Fail-Closed Symlink Rejection:** The CLI strictly rejects symbolic links (`os.path.islink`) across input parameters to prevent file-descriptor hijacking.
- **Subprocess Security:** Binary invocations strictly avoid `shell=True`, preventing command-injection attacks.
- **Automated Secret Redaction:** All console outputs and JSON payloads scrub sensitive credentials (`AKIA...`, `ghp_...`, private keys).
