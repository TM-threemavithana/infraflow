# InfraFlow Unified Platform Developer Experience, CLI & Diagnostic Engine Architecture (Milestone G10.1)

**Status:** IMPLEMENTED  
**Version:** v0.7.0 / G10.1  
**Lead Architect:** Principal Platform Engineer, DevEx Architect, DevSecOps Lead  
**Canonical Repository:** `TM-threemavithana/infraflow`  
**Security Classification:** Highly Confidential Enterprise Architecture Contract  

---

## 1. Executive Summary & Problem Context

Prior to Milestone G10.1, the InfraFlow enterprise platform maintained specialized Python and Shell automation scripts distributed across the repository:
- `scripts/validate-consumer.py`: Consumer onboarding configuration and workflow validation (G08.3).
- `scripts/plan-fleet-upgrade.py`: Fleet inventory discovery and upgrade dry-run planning (G08.4).
- `scripts/simulate-drift.py`: Continuous state and speculative drift detection simulation (G09.2).
- `scripts/orchestrate-campaign.py`: Staged campaign orchestration and Canary Gate verification (G09.3).
- `scripts/verify-operational-maturity.py`: Central multi-tenant governance aggregation (G09.4).

While technically comprehensive and rigorously tested (550+ unit tests, 400+ quality gates), this distributed layout created a fragmented developer experience (DevEx) for platform engineers and application consumers:
1. **Tooling Fragmentation:** Platform engineers were required to recall disparate CLI arguments, input formats, and environment requirements across 5+ independent scripts.
2. **Environment Diagnostics Absence:** Developers onboarding or debugging CI/CD failures had no standardized, non-destructive mechanism to verify local dependencies (`terraform`, `conftest`, `tflint`, `trivy`, `actionlint`, `zizmor`) or repository health before running CI/CD tasks.
3. **Cryptic Policy Violations:** Raw Open Policy Agent (OPA) / Conftest deny messages provided limited context, lacking standardized policy IDs, resource attribution, line numbers, or actionable remediation guidance.
4. **DevSecOps Inconsistency:** Output sanitization, symlink guards, and exit code propagation differed slightly across utility scripts.

**Milestone G10.1 introduces the InfraFlow Unified Platform CLI (`scripts/infraflow-cli.py`)**: a centralized, single-binary-like command-line utility providing unified ergonomics, automated environment diagnostics, non-destructive policy evaluation with intelligent error enrichment, continuous drift detection, and fleet campaign management.

---

## 2. Core Architecture & Design Principles

```
                                    ┌──────────────────────────────────────────────┐
                                    │         Developer / CI-CD Operator           │
                                    └──────────────────────┬───────────────────────┘
                                                           │
                                                           ▼
                                    ┌──────────────────────────────────────────────┐
                                    │             infraflow [SUBCOMMAND]           │
                                    │        (scripts/infraflow-cli.py)            │
                                    └──────┬───────────────┬───────────────┬───────┘
                                           │               │               │
                 ┌─────────────────────────┼───────────────┴───────────────┼─────────────────────────┐
                 │                         │                               │                         │
                 ▼                         ▼                               ▼                         ▼
      ┌──────────────────────┐  ┌──────────────────────┐        ┌──────────────────────┐  ┌──────────────────────┐
      │   infraflow doctor   │  │  infraflow validate  │        │   infraflow drift    │  │  infraflow upgrade   │
      └──────────┬───────────┘  └──────────┬───────────┘        └──────────┬───────────┘  └──────────┬───────────┘
                 │                         │                               │                         │
        ┌────────┴────────┐       ┌────────┴────────┐             ┌────────┴────────┐       ┌────────┴────────┐
        │ 12 Diagnostics  │       │ Consumer Config │             │ Snapshot Diff   │       │ Dry-Run Plan    │
        │ Health Matrix   │       │ Fleet Manifest  │             │ Telemetry Emit  │       │ Rollout Stages  │
        │ Non-Destructive │       │ OPA Enhancer    │             │ Zero-Drift Gate │       │ Canary Gate     │
        └─────────────────┘       └─────────────────┘             └─────────────────┘       └─────────────────┘
                 │                         │                               │                         │
                 └─────────────────────────┼───────────────────────────────┼─────────────────────────┘
                                           │
                                           ▼
                                ┌──────────────────────────────────────────────┐
                                │      Platform Defense & Isolation Layer      │
                                ├──────────────────────────────────────────────┤
                                │  • Automated Secret Scrubbing (Tokens, Keys) │
                                │  • Symlink Prohibitions (os.path.islink)     │
                                │  • Safe Subprocess (Strictly no shell=True)  │
                                │  • $0.00 Spend Guarantee (Offline Simulation)│
                                └──────────────────────────────────────────────┘
```

### Architectural Tenets:
1. **Ergonomic Unified Entrypoint:** Consolidates all platform commands under `infraflow` with standardized flags (`--json`, `--verbose`, `--no-color`).
2. **Non-Destructive Execution:** Purely read-only diagnostics and speculative simulations. No live cloud state manipulation; strictly zero cloud spending ($0.00).
3. **Fail-Closed Security Invariants:** Symlinks are strictly prohibited (`os.path.islink`); dangerous directory traversals (`..`) are rejected; subprocess invocations strictly reject `shell=True`.
4. **Recursive Secret Sanitization:** All console streams and structured JSON exports automatically redact AWS access keys, GitHub personal access tokens, private keys, and credential strings before emission.
5. **Intelligent Policy Error Enrichment:** Transforms raw Rego deny strings into structured diagnostics with human-readable Policy IDs, severity classifications, resource names, source line numbers, and actionable remediation steps.

---

## 3. Subcommand Specifications

### 3.1 `infraflow doctor` — Platform Health Matrix
The `doctor` engine non-destructively evaluates the local developer environment and platform repository across 12 distinct dimensions:

| Check ID | Component Checked | Required Baseline | Evaluation Mechanism | Status Outcomes |
|---|---|---|---|---|
| `DOC-01-PYTHON` | Python Runtime | `>= 3.10` | `sys.version_info` | PASS / FAIL |
| `DOC-02-TERRAFORM` | HashiCorp Terraform | `>= 1.6.0` | `terraform version -json` | PASS / WARN / FAIL |
| `DOC-03-GIT` | Git Version Control | `>= 2.0` | `git --version` | PASS / FAIL |
| `DOC-04-TFLint` | TFLint IaC Linter | Available | `tflint --version` across PATH & local bin | PASS / WARN |
| `DOC-05-TRIVY` | Trivy Security Scanner | Available | `trivy --version` across PATH & local bin | PASS / WARN |
| `DOC-06-CONFTEST` | Conftest (OPA Engine) | Available | `conftest --version` across PATH & local bin | PASS / FAIL |
| `DOC-07-ACTIONLINT` | Actionlint Workflow Linter | Available | `actionlint -version` across PATH & local bin | PASS / WARN |
| `DOC-08-ZIZMOR` | Zizmor Workflow Auditor | Available | `zizmor --version` across PATH & local bin | PASS / WARN |
| `DOC-09-DIRS` | Platform Hierarchy | 6 core directories | Filesystem presence verification | PASS / FAIL |
| `DOC-10-POLICIES` | Core Rego Policies | 5 critical contracts | Policy existence & manifest check | PASS / FAIL |
| `DOC-11-PYDEPS` | Python Dependencies | PyYAML, cryptography | Module importability validation | PASS / FAIL |
| `DOC-12-GITSTATE` | Git Workspace State | Clean working tree | `git status --porcelain`, branch & SHA | PASS / WARN |

**Exit Codes:**
- `0`: All checks passed, or warnings present without `--strict`.
- `1`: One or more hard failures detected, or warnings present with `--strict`.

### 3.2 `infraflow validate` — Governance & Policy Engine
Handles three distinct validation workloads:
1. **Consumer Configuration (`--config`)**: Reuses `validate-consumer.py` contract validation, verifying schema version, identity formats, adapter mappings, directory containment, and workflow pinning.
2. **Fleet Manifest (`--manifest`)**: Validates `fleet-manifest.yaml` schema, candidate commit SHA format (40 hex chars), and consumer registries.
3. **OPA Policy Evaluation (`--policy-file`, `--input-file`)**: Invokes Conftest against target configurations and routes raw output through the **Policy Error Enhancement Engine**.

### 3.3 `infraflow drift` — Continuous State & Speculative Drift
Wraps the G09.2 continuous state drift detection simulation engine:
- Evaluates expected vs observed state snapshots across AWS, Azure, and GCP.
- Classifies drift into `NO_DRIFT`, `ATTRIBUTE_DRIFT`, `UNTRACKED_RESOURCE`, `RESOURCE_DELETED`, `UNKNOWN_RESOURCE`, or `STATE_INCONSISTENCY`.
- Supports `--enforce-zero-drift` to act as an automated CI/CD gating mechanism.
- Emits structured telemetry via `--emit-telemetry`.

### 3.4 `infraflow upgrade` — Fleet Upgrade Campaigns & Lifecycle
Integrates fleet upgrade planning (`plan-fleet-upgrade.py`) and campaign orchestration (`orchestrate-campaign.py`):
- Generates dry-run upgrade plans (`--plan`).
- Executes local staged rollout updates (`--apply`).
- Triggers automated rollback to known-good baseline SHAs (`--rollback`).
- Enforces Canary Gate promotion constraints.

---

## 4. Policy Error Enhancement Engine

### 4.1 Problem Statement
When Conftest evaluates Rego policies against HCL ASTs or Plan JSONs, raw failures often print as dense, unstructured strings:
```
FAIL - fixtures/invalid-aws/main.tf - aws.s3 - Resource 'aws_s3_bucket.bad_acl_bucket' must not specify public ACL 'public-read'
```
Developers onboarding to InfraFlow frequently struggle to determine:
1. Which enterprise security standard or policy ID is being violated?
2. What severity level does this breach carry?
3. Where in the configuration file is the resource located?
4. What is the exact remediation step required to resolve it?

### 4.2 Error Enhancement Pipeline

```
  Raw Conftest Output (JSON or Text)
                 │
                 ▼
     [ 1. Regex Entity Extractor ] ──► Extracts resource name (e.g., aws_s3_bucket.bad_acl_bucket)
                 │
                 ▼
     [ 2. Knowledge Base Matcher ] ──► Maps message patterns to Policy ID, Severity & Remediation
                 │
                 ▼
     [ 3. AST Source Line Finder ] ──► Scans target input file to pinpoint declaration line number
                 │
                 ▼
     [ 4. Enhanced Diagnostic Output ]
```

### 4.3 Policy Mapping Matrix (Excerpt)

| Rego Namespace | Violation Pattern | Mapped Policy ID | Severity | Remediation Advice |
|---|---|---|---|---|
| `aws.s3` | `public ACL` | `AWS-SEC-S3-ACL-001` | **CRITICAL** | Remove public ACL ('public-read' / 'website'); use private ACL and IAM policies. |
| `aws.s3` | `block_public_acls` | `AWS-SEC-S3-PAB-001` | **CRITICAL** | Enable all 4 public access block protections on `aws_s3_bucket_public_access_block`. |
| `azure.storage_backend` | `min_tls_version` | `AZURE-SEC-TLS-001` | **HIGH** | Set `min_tls_version = 'TLS1_2'` on `azurerm_storage_account`. |
| `azure.storage_backend` | `allow_nested_items_to_be_public`| `AZURE-SEC-PUB-001` | **CRITICAL** | Set `allow_nested_items_to_be_public = false` to prevent anonymous blob exposure. |
| `azure.entra_oidc` | `token.actions.githubusercontent.com` | `SEC-OIDC-ISSUER-001` | **CRITICAL** | Federated credential issuer must strictly match official GitHub OIDC issuer URI. |
| `gcp.storage_backend` | `Uniform Bucket-Level Access` | `GCP-SEC-GCS-UBLA-001` | **HIGH** | Set `uniform_bucket_level_access = true` (CIS GCP 5.2). |
| `gcp.wif_oidc` | `wildcard` | `SEC-OIDC-WILDCARD-001`| **CRITICAL** | Replace wildcard subject/audience bindings with exact repository and branch claims. |
| `common.tags` | `missing mandatory 'tags' block` | `COMMON-TAG-001` | **MEDIUM** | Add mandatory `tags` block with `Environment`, `Project`, and `ManagedBy`. |

---

## 5. Security & Threat Modeling (STRIDE)

| Threat Category | Potential Vector | Platform Defense Invariant |
|---|---|---|
| **Spoofing** | Masquerading as valid platform ref | Canonical platform reference validation (`TM-threemavithana/infraflow`). |
| **Tampering** | Symbolic link hijacking / path escape | Explicit symlink check (`os.path.islink`) and directory containment checks. |
| **Repudiation** | Unaudited diagnostic or drift execution | Structured telemetry emission with deterministic SHA-256 event digests. |
| **Information Disclosure** | Secrets leaked in console or logs | Multi-tier regex redaction engine (`SecretSanitizer`) scrubbing tokens and keys. |
| **Denial of Service** | Malformed input causing uncontrolled loops | Strict JSON schema parsing, file size bounds, and deterministic recursion limits. |
| **Elevation of Privilege** | Subprocess shell command injection | Subprocess calls strictly reject `shell=True`; binary paths are resolved safely. |

---

## 6. Verification and Acceptance Criteria

Milestone G10.1 is verified by:
1. **Dedicated Unit Test Suite:** `tests/test_cli.py` (19 automated tests covering version, doctor, validation, error enhancement, drift, upgrade, secret redaction, and symlink defenses).
2. **Platform Test Suite Integrity:** All 554 platform unit tests across G01–G10 pass with zero failures.
3. **Validation Harness Integration:** Section 26 of `scripts/validate-local.sh` (13 quality checks) completing with 100% pass rate.
4. **Static Analysis & Security Auditing:** Zero warnings from `shellcheck` across `validate-local.sh`.
