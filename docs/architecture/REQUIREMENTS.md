# InfraFlow — Functional & Security Requirements

## 1. Executive Summary

**InfraFlow** is a modular, multi-cloud Infrastructure Delivery Platform engineered for scalable, secure, and maintainable Terraform CI/CD automation across distributed GitHub repositories.

This document defines the functional, non-functional, security, and governance requirements governing the platform foundation (Milestone G01) and reusable CI/CD core engine (Milestone G02).

---

## 2. Core Architecture Principles

1. **Single Reusable Core (DRY Engine)**:
   Terraform verification and testing logic (`fmt`, `init`, `validate`, `test`) is implemented once in a reusable GitHub Actions workflow (`workflow_call`) and consumed across diverse repositories without duplicate pipeline YAML.
2. **Provider Neutrality by Design**:
   The reusable core operates completely decoupled from specific cloud vendors (AWS, Azure, GCP). All cloud-specific concerns (OIDC authentication, remote state management, plan/apply lifecycles) reside in decoupled provider adapters.
3. **Zero Trust & Least Privilege**:
   Workflows run with the absolute minimum `GITHUB_TOKEN` permissions (`contents: read`). Pull request validation workflows never require, access, or expose cloud credentials.
4. **Strict Input Sanitization & Defensive Guardrails**:
   Reusable workflows must guard against path traversal, command injection, and illegal parameter states before executing any binary on the runner.
5. **Zero-Cost Local & CI Validation**:
   The platform core and test suites must run in $0-cost environments (local workstations and standard free GitHub-hosted runners) without requiring paid cloud infrastructure or commercial tooling.
6. **Immutable Supply Chain**:
   All third-party GitHub Actions must be pinned to verified 40-character commit SHAs to prevent supply chain tampering.

---

## 3. Functional Requirements

| ID | Requirement Category | Description | Scope / Target |
|---|---|---|---|
| **FR-01** | **Reusable Workflow Interface** | Provide a central GitHub Actions reusable workflow callable via `workflow_call` by any internal or external GitHub repository. | G02 Core |
| **FR-02** | **Configurable Terraform Version** | Caller repositories must be able to specify the exact Terraform version (defaulting to a tested stable version e.g. `1.10.4`). | Inputs |
| **FR-03** | **Configurable Working Directory** | Caller repositories must be able to specify one or more relative subdirectories where the Terraform code resides. | Inputs |
| **FR-04** | **Input Path Validation** | Reject invalid working directories, path traversal attempts (`../`), and shell metacharacters prior to checkout or execution. | Security Guard |
| **FR-05** | **Syntax & Format Verification** | Execute `terraform fmt -check -diff -recursive` to enforce canonical code formatting. Provide an opt-out boolean flag if needed (`enable-fmt-check`). | Automation |
| **FR-06** | **Cloud-Free Initialization** | Execute `terraform init -backend=false` without requiring remote backend credentials or network access to cloud storage. | Automation |
| **FR-07** | **Static Configuration Validation** | Execute `terraform validate` to verify syntactical and internal consistency across resources, variables, and outputs. | Automation |
| **FR-08** | **Native Terraform Testing** | Execute `terraform test` utilizing Terraform's built-in testing framework (`.tftest.hcl`), supporting unit and contract testing without external runners. | Automation |
| **FR-09** | **Feature Flagging for Steps** | Allow consuming repositories to selectively enable/disable formatting check, validation, and test suites via workflow inputs. | Workflow Inputs |
| **FR-10** | **Structured Workflow Outputs** | Emit structured step outcomes (`fmt-status`, `validate-status`, `test-status`, `summary`) back to the calling job. | Workflow Outputs |
| **FR-11** | **Cloud-Free Reference Module** | Provide a comprehensive reference Terraform module utilizing `terraform_data` with complete input validation and unit tests. | Examples |
| **FR-12** | **Reference Consumer Workflow** | Provide a fully working sample workflow illustrating how external consuming repositories invoke InfraFlow. | Examples |
| **FR-13** | **Local Validation Harness** | Provide an automated local script (`validate-local.sh`) validating workflows, Terraform code, and negative fixtures offline. | Developer Tooling |

---

## 4. Security & Hardening Requirements

| ID | Security Area | Requirement & Implementation Standard | Severity |
|---|---|---|---|
| **SEC-01** | **Token Permissions** | Workflows and jobs must explicitly declare `permissions: contents: read`. Workflows must disallow elevated default permissions. | Critical |
| **SEC-02** | **No Cloud Credentials in PRs** | Pull request verification jobs must not request, access, or expose cloud credentials (AWS IAM keys, Azure Client Secrets, GCP Service Account keys). | Critical |
| **SEC-03** | **No `pull_request_target`** | Untrusted pull request code must never execute in the context of the base repository or with privileged tokens. Only standard `pull_request` triggers are allowed. | Critical |
| **SEC-04** | **Script Injection Defense** | No GitHub expression (`${{ inputs.* }}` or `${{ github.* }}`) may be inlined directly inside `run:` script strings. All values must be mapped to POSIX environment variables. | Critical |
| **SEC-05** | **Action SHA Pinning** | All external GitHub Actions (`actions/checkout`, `hashicorp/setup-terraform`) must be pinned to immutable 40-character commit SHAs with semantic tag comments. | High |
| **SEC-06** | **Directory Traversal Prevention** | The working directory input must be validated via POSIX regex ensuring only relative, safe directory paths are navigated. Path traversal sequences (`..`) must trigger immediate exit. | High |
| **SEC-07** | **No Sensitive Artifacts** | Plan files or debug logs containing potential secrets, tokens, or configuration values must not be published to unencrypted artifacts or unmasked logs. | High |
| **SEC-08** | **Negative Testing** | Negative test fixtures must explicitly prove that syntax errors, unformatted code, failing tests, and malicious directory paths are rejected with nonzero exit codes. | High |

---

## 5. Non-Functional Requirements

- **Performance**: Reusable core validation should complete in under 2 minutes on standard GitHub-hosted `ubuntu-latest` runners.
- **Maintainability**: Zero external wrapper dependencies (e.g. no Terragrunt or complex Docker images required for basic CI validation). Uses standard Terraform CLI and native GitHub Actions.
- **Extensibility**: Clean contract allowing Milestone G03 adapters (AWS, Azure, GCP) to hook into the pipeline seamlessly without breaking existing callers.
- **Compatibility**: Supports Terraform versions `>= 1.6.0` through `1.11.x+` (supporting native `terraform test` and `terraform_data`).

---

## 6. Verification & Traceability Matrix

| Requirement | Implementation Artifact | Local Verification Method |
|---|---|---|
| FR-01, FR-02, FR-03, FR-09, FR-10 | `.github/workflows/reusable-tf-validate.yml` | `actionlint` schema inspection |
| FR-04, SEC-04, SEC-06 | `.github/workflows/reusable-tf-validate.yml` | `scripts/validate-local.sh` malicious input test |
| FR-05, FR-06, FR-07, FR-08 | `.github/workflows/reusable-tf-validate.yml` | `terraform fmt`, `init`, `validate`, `test` CLI execution |
| FR-11 | `examples/cloud-free-module/` | `terraform init -backend=false && terraform test` |
| FR-12 | `examples/consumer-workflow/` | `actionlint` lint verification |
| SEC-01, SEC-03, SEC-05 | `.github/workflows/*.yml` | Automated actionlint & code review audit |
| SEC-08 | `fixtures/*` | Negative test fixture runner in `scripts/validate-local.sh` |
