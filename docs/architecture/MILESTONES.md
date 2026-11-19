# InfraFlow — Delivery Milestones & Acceptance Criteria

## 1. Program Roadmap Overview

InfraFlow is structured into five progressive delivery milestones:

| Milestone | Title | Focus Area | Status |
|---|---|---|---|
| **G01** | **Foundation and Architecture** | Architecture, threat model, repository structure, requirements, adapters spec. | **In Progress (Active)** |
| **G02** | **Reusable Terraform CI/CD Core** | Reusable `workflow_call` workflow, input validation guard, cloud-free module, tests, negative fixtures. | **In Progress (Active)** |
| **G03** | **Multi-Cloud Adapters & OIDC** | AWS, Azure, GCP provider adapters using passwordless Workload Identity Federation. | Backlog (Future) |
| **G04** | **Policy as Code & Drift Detection** | OPA/Checkov/Trivy policy enforcement, automated scheduled drift detection pipelines. | Backlog (Future) |
| **G05** | **Enterprise Governance & Fleet Rollout** | Multi-repo orchestration, centralized compliance dashboard, automated upgrade campaigns. | Backlog (Future) |

---

## 2. Milestone G01 — Acceptance Criteria (Foundation & Architecture)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G01-01** | Environment Assessment | Operating environment inspected (WSL2 Ubuntu, Windows 11, Terraform, Git, Docker). | Local command execution log | PASS |
| **AC-G01-02** | Repository Structure | Modular, clean directory structure created with clear separation of workflows, docs, examples, fixtures, and scripts. | Filesystem inspection | PASS |
| **AC-G01-03** | Functional Requirements | Complete functional, non-functional, and verification requirements defined. | `docs/architecture/REQUIREMENTS.md` | PASS |
| **AC-G01-04** | Architecture Specification | System design, two-tier architecture, workflow contracts, and versioning documented with Mermaid diagrams. | `docs/architecture/ARCHITECTURE.md` | PASS |
| **AC-G01-05** | Cloud Adapters Specification | Future AWS, Azure, and GCP adapters specified with OIDC authentication and state backends. | `docs/architecture/ADAPTERS.md` | PASS |
| **AC-G01-06** | Threat Model & Trust Boundaries | STRIDE analysis, trust boundaries, injection attacks, and action supply chain risks documented. | `docs/architecture/THREAT_MODEL.md` | PASS |
| **AC-G01-07** | Acceptance Criteria Definition | All criteria and gates documented for current and subsequent milestones. | `docs/architecture/MILESTONES.md` | PASS |

---

## 3. Milestone G02 — Acceptance Criteria (Reusable Terraform CI/CD Core)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G02-01** | Reusable Workflow Implementation | Implement `.github/workflows/reusable-tf-validate.yml` using `workflow_call`. | `actionlint` linting | PASS |
| **AC-G02-02** | Strict Input Sanitization | Implement defensive bash guard rejecting path traversal (`..`), disallowed characters, absolute paths, and SemVer < 1.6.0. | Script and fixture execution | PASS |
| **AC-G02-03** | Security Hardening | Pinned 40-character action SHAs, minimal `permissions: contents: read`, zero secrets, no `pull_request_target`, SHA256 verified actionlint in CI. | Workflow review & actionlint | PASS |
| **AC-G02-04** | Terraform Automation Steps | Core workflow executes `terraform fmt -check`, `terraform init -backend=false`, `terraform validate`, and `terraform test`. | CLI & workflow execution | PASS |
| **AC-G02-05** | Cloud-Free Reference Module | Production-quality example module in `examples/cloud-free-module/` using `terraform_data` with variable validations and unit tests. | `terraform test` passes | PASS |
| **AC-G02-06** | Negative Test Fixtures | Fixtures proving expected failure modes on syntax errors, unformatted code, failing tests, and malicious directory traversal. | Automated execution in validation script | PASS |
| **AC-G02-07** | Consuming Workflow Example | Realistic consumer workflow in `examples/consumer-workflow/` illustrating external repository invocation. | Actionlint validation | PASS |
| **AC-G02-08** | Automated Local Validation Harness | Script `scripts/validate-local.sh` providing offline, zero-cost automated verification of all gates (22/22 checks). | Complete script execution | PASS |
| **AC-G02-09** | Documentation & README | Clear root `README.md` with usage instructions, input/output documentation, and architecture diagrams. | Documentation review | PASS |

---

## 4. Quality Gate Definitions

To achieve status **PASS** for G01 and G02:
1. Every G01 document must exist, be fully elaborated, and be internally consistent.
2. The reusable workflow and caller example must pass `actionlint` without errors or warnings.
3. The cloud-free Terraform module must pass format check, validation, and all unit test assertions.
4. All negative test fixtures must fail as expected with appropriate error codes.
5. The local validation runner script must complete with exit code 0.
6. Git status must remain clean of untracked temporary files.
7. Any capability not executable locally (e.g. live GitHub-hosted cross-repository call) must be transparently designated **NOT TESTED**.
