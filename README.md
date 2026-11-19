# InfraFlow — Reusable Multi-Cloud Infrastructure Delivery Platform

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI Status](https://img.shields.io/badge/CI-actionlint%20%7C%20terraform%20test-brightgreen.svg)](#local-validation)
[![Terraform](https://img.shields.io/badge/Terraform-%3E%3D1.6.0-844FBA.svg)](https://www.terraform.io)

**InfraFlow** is an enterprise-oriented, secure, and maintainable Terraform delivery platform engineered to be reused across independent GitHub repositories.

InfraFlow separates infrastructure delivery into two distinct layers:
1. **Tier 1 — Reusable Provider-Neutral CI/CD Core**: A standardized GitHub Actions workflow (`workflow_call`) executing linting, static validation, and native testing (`.tftest.hcl`) with **zero cloud credentials** and least-privilege tokens.
2. **Tier 2 — Modular Cloud Adapters (AWS, Azure, GCP)**: Isolated adapters handling OIDC authentication, remote state backends, and speculative planning/applies on protected branches.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph Consumers["Consuming Repositories (Independent App / Infra Repos)"]
        Repo1["repo-networking\n(.github/workflows/ci.yml)"]
        Repo2["repo-services\n(.github/workflows/ci.yml)"]
        Repo3["repo-data-platform\n(.github/workflows/ci.yml)"]
    end

    subgraph CorePlatform["InfraFlow Core Platform — Tier 1 (Provider-Neutral)"]
        Guard["Input Sanitization & Security Guard"]
        Toolchain["Terraform Toolchain (SHA-Pinned Actions)"]
        Fmt["terraform fmt -check -diff -recursive"]
        Init["terraform init -backend=false"]
        Val["terraform validate"]
        Test["terraform test (Native .tftest.hcl)"]
        Report["Structured Outputs & Markdown Step Summary"]

        Guard --> Toolchain
        Toolchain --> Fmt
        Fmt --> Init
        Init --> Val
        Val --> Test
        Test --> Report
    end

    subgraph Adapters["Future Tier 2 Adapters (Milestone G03)"]
        AWS["AWS Adapter (OIDC + S3)"]
        Azure["Azure Adapter (OIDC + Blob)"]
        GCP["GCP Adapter (OIDC + GCS)"]
    end

    Repo1 -->|"workflow_call (PR Check)"| Guard
    Repo2 -->|"workflow_call (PR Check)"| Guard
    Repo3 -->|"workflow_call (PR Check)"| Guard

    Report -.->|"On Merge to Main"| AWS
    Report -.->|"On Merge to Main"| Azure
    Report -.->|"On Merge to Main"| GCP
```

---

## Reusable Workflow Specification

The core reusable workflow is located at [`.github/workflows/reusable-tf-validate.yml`](.github/workflows/reusable-tf-validate.yml).

### Inputs Contract

| Input Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `terraform-version` | `string` | No | `'1.10.4'` | Terraform CLI version to install. Enforced `>= 1.6.0` and validated against SemVer format. |
| `working-directory` | `string` | No | `'.'` | Relative directory containing Terraform configuration. Traversal (`..`), absolute paths, and workspace escapes are blocked. |
| `enable-fmt-check` | `boolean` | No | `true` | Enforces canonical styling via `terraform fmt -check`. |
| `enable-validate` | `boolean` | No | `true` | Validates configuration integrity via `terraform validate`. |
| `enable-test` | `boolean` | No | `true` | Runs native unit tests via `terraform test`. |
| `test-var-file` | `string` | No | `''` | Optional relative path to a `.tfvars` file for test variables. |

### Outputs Contract

| Output Name | Type | Description |
|---|---|---|
| `fmt-status` | `string` | Formatting check outcome (`success`, `failure`, `skipped`). |
| `validate-status` | `string` | Validation check outcome (`success`, `failure`, `skipped`). |
| `test-status` | `string` | Native test suite outcome (`success`, `failure`, `skipped`). |
| `summary` | `string` | Aggregated execution summary string. |

---

## Consuming Repository Quick Start

> **NOTE**: The example below uses placeholders (`YOUR_OWNER/YOUR_REPOSITORY`). Prior to publishing release tag `v1`, callers must reference an immutable commit SHA (`@<40-char-sha>`) or active branch. See [Consumer Workflow Guide](examples/consumer-workflow/README.md) for full instructions.

Create `.github/workflows/infraflow-validate.yml` in your consumer repository:

```yaml
name: "Terraform CI"

on:
  pull_request:
    branches: [main]
    paths:
      - "terraform/**"
      - ".github/workflows/infraflow-validate.yml"

permissions:
  contents: read

jobs:
  validate:
    name: "Validate Terraform"
    # Replace YOUR_OWNER/YOUR_REPOSITORY with your GitHub org/repo
    # Replace YOUR_INFRAFLOW_COMMIT_SHA with your commit SHA (e.g., 8a3f9c...) or @v1 once published
    uses: YOUR_OWNER/YOUR_REPOSITORY/.github/workflows/reusable-tf-validate.yml@YOUR_INFRAFLOW_COMMIT_SHA
    with:
      terraform-version: "1.10.4"
      working-directory: "terraform"
      enable-fmt-check: true
      enable-validate: true
      enable-test: true
```

For full multi-module matrix execution examples, see the [Consumer Workflow Guide](examples/consumer-workflow/README.md).

---

## Security Architecture & Defenses

1. **Least-Privilege Token Permissions**: Workflows run with `permissions: contents: read`. No write permissions are granted to pull request jobs.
2. **Zero Cloud Credentials in PR**: Pull request validation requires zero AWS, Azure, or GCP credentials.
3. **No `pull_request_target`**: Prevents untrusted fork code from executing with base repository privileges.
4. **Script Injection Mitigation**: All workflow inputs are mapped to POSIX environment variables before shell script execution. No raw `${{ inputs.* }}` expressions are evaluated directly inside `run:` strings.
5. **Directory Traversal & Containment**: Inputs are strictly validated against regex allowlists; absolute paths (`/`), tildes (`~`), and path traversal (`..`) are rejected before checkout. Post-checkout checks enforce that the canonical working directory is contained within `$GITHUB_WORKSPACE`.
6. **Immutable Action Pinning**: External actions are pinned to full 40-character commit SHAs:
   - `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` (# v4.2.2)
   - `hashicorp/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd` (# v3.1.2)
7. **Supply Chain Hardened CI**: Platform CI downloads and executes `actionlint` v1.7.7 verified against an immutable SHA256 checksum.

---

## Release Readiness & Verification Status

### Locally Verified Capabilities (22/22 Automated Checks)
- **Workflow Schema & Syntax**: Validated with `actionlint` across all workflows.
- **Terraform Formatting**: Validated via `terraform fmt -check` on cloud-free modules.
- **Backend-Free Init**: Validated via `terraform init -backend=false`.
- **Static Validation**: Validated via `terraform validate`.
- **Native Unit Testing**: Validated via `terraform test` (6 passed unit assertions).
- **Negative Fixture Rejection**: Verified failure detection on invalid syntax, unformatted code, and failing assertions.
- **Input Guard & Workspace Containment**: 12 automated security tests exercising path traversal, injection payloads, invalid SemVer, version `< 1.6.0`, absolute paths, and missing directories.

### Remotely Unverified Capabilities (Pending Remote Release)
- **Live GitHub-Hosted Runner Execution**: Cannot be executed offline; requires pushing to a remote repository with active GitHub Actions runners.
- **Live Cross-Repository Invocations**: Requires a published remote repository with cross-repository access enabled.

---

## How to Create the First Immutable Release

When ready to publish the first public release to GitHub:

```bash
# 1. Review status and create the initial commit on main
git add .
git commit -m "feat(core): initial release of InfraFlow reusable terraform delivery platform"

# 2. Add remote origin (replace with your repository URL)
git remote add origin https://github.com/YOUR_OWNER/YOUR_REPOSITORY.git

# 3. Push main branch
git push -u origin main

# 4. Tag the immutable semantic release
git tag -a v1.0.0 -m "Release v1.0.0: Initial release of InfraFlow CI/CD Core"

# 5. Create the floating major tag
git tag -fa v1 -m "Release v1"

# 6. Push tags to GitHub
git push origin v1.0.0 v1

# 7. Configure Cross-Repository Access (if repository is private)
# Navigate to: Settings -> Actions -> General -> Access
# Select: "Accessible from repositories in the '{organization}' organization"
```

---

## Repository Structure

```
infraflow/
├── .github/
│   └── workflows/
│       ├── reusable-tf-validate.yml   # Core reusable workflow (G02)
│       └── ci.yml                     # Platform self-testing workflow
├── docs/
│   └── architecture/
│       ├── ARCHITECTURE.md            # System design & two-tier model
│       ├── REQUIREMENTS.md            # Functional & security requirements
│       ├── THREAT_MODEL.md            # STRIDE threat model & trust boundaries
│       ├── ADAPTERS.md                # Future AWS, Azure, GCP adapter specs
│       └── MILESTONES.md              # Milestones & acceptance criteria (G01-G05)
├── examples/
│   ├── cloud-free-module/             # Cloud-neutral reference module (terraform_data)
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   ├── versions.tf
│   │   └── tests/
│   │       └── unit.tftest.hcl
│   └── consumer-workflow/             # Sample consumer repository workflow & guide
│       ├── .github/workflows/
│       │   └── infraflow-consume.yml
│       └── README.md
├── fixtures/                          # Negative testing verification fixtures
│   ├── invalid-syntax/
│   ├── unformatted/
│   └── failing-test/
├── scripts/
│   └── validate-local.sh              # Local automated verification harness
├── .gitignore
├── LICENSE
└── README.md
```

---

## Local Validation

InfraFlow includes an automated, offline local test harness executing all 22 quality gates:

```bash
chmod +x scripts/validate-local.sh
./scripts/validate-local.sh
```

---

## Documentation Links

- [System Architecture](docs/architecture/ARCHITECTURE.md)
- [Requirements Specification](docs/architecture/REQUIREMENTS.md)
- [Threat Model & Trust Boundaries](docs/architecture/THREAT_MODEL.md)
- [Cloud Adapters Specification](docs/architecture/ADAPTERS.md)
- [Milestones & Acceptance Criteria](docs/architecture/MILESTONES.md)
- [Consumer Integration Guide](examples/consumer-workflow/README.md)
