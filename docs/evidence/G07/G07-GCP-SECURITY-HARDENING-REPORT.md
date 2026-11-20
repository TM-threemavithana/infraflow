# InfraFlow — GCP Adapter Security Hardening & Offline Regression Report
**Milestone:** G07.3 — GCP Adapter Security Hardening and Offline Validation  
**Date:** 2026-11-21  
**Classification:** Enterprise Security Audit & Adversarial Verification Report  
**Branch:** `feature/g07-gcp-adapter`  
**Base Commit:** `4a5f8d19560b0602871934cdc82cf3cb8fe6b953`  
**Published Baseline:** `v0.4.0`  
**Status:** ALL GATES PASSED (276/276 Checks Clean, 197 Python Tests, 128 Rego Tests, 30 Adversarial Vectors)  
**Cloud Spend:** $0.00 (Strictly Offline & Cloud-Free)

---

## 1. Executive Summary

Milestone **G07.3: GCP Adapter Security Hardening and Offline Validation** conducted a comprehensive, independent security audit and adversarial evaluation of the Google Cloud Platform (GCP) adapter implemented in G07.2. 

The primary goals were:
1. Reconcile and audit the Open Policy Agent (OPA) / Conftest test suite count discrepancy discovered between G06 (89 tests) and G07.2 (120 tests vs 123 expected).
2. Deeply audit the GCP Workload Identity Federation (WIF) threat model, OIDC claim mappings, CEL conditions, and principal formatting rules.
3. Review and harden the reusable workflow (`reusable-tf-gcp.yml`) against path traversal, symlink escapes, workflow gate bypasses, and unencrypted ephemeral plan leakage.
4. Harden Google Cloud Storage (GCS) state backend policies against empty prefixes, overprivileged primitive IAM roles (`roles/owner`, `roles/editor`), and public access primitives.
5. Implement a comprehensive 30-vector adversarial integration test suite (`tests/test_gcp_adversarial_integration.py`).
6. Update and expand Section 17 of the local verification harness (`scripts/validate-local.sh`) to 26 dedicated GCP checks (increasing total platform checks from 272 to 276).
7. Ensure zero regressions across all historical milestones (G01 through G06).

All implementation and verification activities were executed strictly offline with zero live cloud credentials and zero cloud expenditure ($0.00).

```
==============================================================================
>>> Summary of Validation Results (Milestone G07.3)
==============================================================================
Total Checks Executed : 276
Passed Checks         : 276
Failed Checks         : 0

>>> ALL G01/G02/G03/G04/G05/G06/G07 QUALITY GATES PASSED SUCCESSFULLY (276/276) <<<
```

---

## 2. OPA Policy Test Count Reconciliation

### 2.1 The Discrepancy & Root Cause Analysis
In Milestone G06, the platform maintained **89 passing Rego policy unit tests**:
- AWS Policies: 35 tests (`policies/aws/oidc_trust_test.rego` + `policies/aws/s3_backend_test.rego`)
- Azure Policies: 4 tests (`policies/azure/storage_network_test.rego`)
- Common Policies: 47 tests (`policies/common/*_test.rego`)
- GCP Storage Policy: 3 tests (`policies/gcp/storage_test.rego`) — *pre-existing legacy baseline*

When Milestone G07.2 was developed:
1. `policies/gcp/wif_oidc_test.rego` was added with 15 test rules.
2. `policies/gcp/storage_backend_test.rego` was added with 16 test rules.
3. An arithmetic error occurred in G07.2 reporting: running `conftest verify -p policies/gcp policies/gcp` reported 18 tests, because it ran `storage_test.rego` (3 tests) + `wif_oidc_test.rego` (15 tests). The 3 tests from `storage_test.rego` were erroneously counted as new tests, resulting in an expected figure of `89 + 18 + 16 = 123 tests`, whereas `89 - 3 + 18 + 16 = 120 tests` were actually executed.

### 2.2 Coverage Expansion & Resolution
During G07.3, both test suites were systematically audited and expanded to verify all new hardening rules:
- `policies/gcp/wif_oidc_test.rego`: Expanded from 15 to **19 unit tests** (+4 tests covering members list inspection, pull request ref rejection, and global WIF pool format).
- `policies/gcp/storage_backend_test.rego`: Expanded from 16 to **20 unit tests** (+4 tests covering empty backend prefix rejection, overprivileged primitive IAM roles, and additional public ACL entities).

Total Rego tests verified by `conftest verify --policy policies policies`:
- **128 tests, 128 passed, 0 failures, 0 exceptions**
  - AWS: 35 tests
  - Azure: 4 tests
  - Common: 47 tests
  - GCP: 42 tests (`storage_test.rego`: 3, `wif_oidc_test.rego`: 19, `storage_backend_test.rego`: 20)

---

## 3. Vulnerability Findings & Security Hardening

The security review discovered and remediated genuine vulnerabilities and defense-in-depth gaps across policies, workflows, and runtime scripts:

### Finding SEC-G07-01 (High): WorkloadIdentityUser `members` List Bypass
- **Location:** `policies/gcp/wif_oidc.rego` (Rule 10)
- **Vulnerability:** Rule 10 checked whether a service account binding allowed organization-wide `attribute.repository_owner` access without an exact repository binding. However, it only evaluated the single-member attribute (`object.get(b, "member", "")`), failing to iterate over the `members` array (`object.get(b, "members", [])`). Consequently, an attacker or developer defining `google_service_account_iam_binding` with a `members` list containing an org-wide principal would bypass the check.
- **Remediation:** Hardened Rule 10 to extract both `member` strings and `members` lists into a unified evaluation set, guaranteeing that any organization-wide owner principal lacking `/attribute.repository/` or `/attribute.repository_id/` is rejected.
- **Verification:** Unit test `test_repository_owner_without_repo_in_members_list_rejected` and Vector 8.

### Finding SEC-G07-02 (Medium): Untrusted Pull Request Ref in CEL Condition
- **Location:** `policies/gcp/wif_oidc.rego` (Rule 6)
- **Vulnerability:** Rule 6 enforced that `attribute_condition` must filter on protected branches (`assertion.ref`). However, a condition checking `assertion.ref == 'refs/pull/123/merge'` would pass the naive check `contains(cond, "assertion.ref")`, potentially allowing an untrusted PR from a fork or external contributor to exchange tokens.
- **Remediation:** Hardened Rule 6 to explicitly reject conditions matching `refs/pull/` strings (`regex.match("(?i)refs/pull/", cond)`), requiring canonical branch or tag references (`refs/heads/`, `refs/tags/`) or environment constraints (`assertion.environment`).
- **Verification:** Unit test `test_pull_request_ref_condition_rejected` and Vector 12.

### Finding SEC-G07-03 (Medium): Missing Input Validation on `policy-directory`
- **Location:** `.github/workflows/reusable-tf-gcp.yml` (`validate-inputs` job)
- **Vulnerability:** The workflow allowed consumers to provide an optional `policy-directory` input, but failed to sanitize it in the `validate-inputs` guard script. A malicious caller could pass path traversal sequences (`../../etc`) or absolute paths (`/etc`), potentially exposing unauthorized filesystem areas during policy scanning.
- **Remediation:** Added Section 13 in the input guard script rejecting absolute paths (`^/`), home directory expansions (`^~`), traversal sequences (`..`), and non-alphanumeric/safe path characters.
- **Verification:** Dedicated tests in `tests/test_gcp_adapter.py` and Section 17.12 of `scripts/validate-local.sh`.

### Finding SEC-G07-04 (High): Bypassable Security Gates via Inputs
- **Location:** `.github/workflows/reusable-tf-gcp.yml` (`validate-inputs` job)
- **Vulnerability:** Inputs `enable-policy-evaluation` and `enable-trivy` were exposed as configurable booleans. A consumer workflow could set `enable-policy-evaluation: false` or `enable-trivy: false`, completely bypassing mandatory DevSecOps gates.
- **Remediation:** Added Section 14 in `validate-inputs` strictly rejecting any attempt to disable policy evaluation or Trivy scanning, failing closed with a fatal error.
- **Verification:** Dedicated tests in `tests/test_gcp_adapter.py` and Vector 27 in adversarial suite.

### Finding SEC-G07-05 (Medium): Workspace Symlink Escape Vulnerability
- **Location:** `.github/workflows/reusable-tf-gcp.yml` (`cloud-free-plan` job)
- **Vulnerability:** Before executing Terraform and security tools, the runner did not verify whether `working-directory`, `var-file`, or `policy-directory` were symbolic links targeting paths outside the cloned repository workspace.
- **Remediation:** Implemented `verify_workspace` step verifying `-L` (symbolic link detection) and canonical path resolution (`cd "${TARGET_PATH}" && pwd -P`) ensuring all execution occurs strictly within `GITHUB_WORKSPACE`.
- **Verification:** Adversarial test Vector 23.

### Finding SEC-G07-06 (Medium): Sensitive Ephemeral Plan Residue on Failure
- **Location:** `.github/workflows/reusable-tf-gcp.yml` (`cloud-free-plan` job)
- **Vulnerability:** During speculative plan generation, `tfplan` and `tfplan.json` were written to disk. If a subsequent step (such as Trivy scanning or Conftest evaluation) failed, raw unencrypted plan files remained on the runner disk.
- **Remediation:** Implemented POSIX trap `trap 'rm -f tfplan tfplan.json' EXIT INT TERM` at the entrypoint of the plan step, guaranteeing artifact deletion under all exit scenarios.
- **Verification:** Adversarial test Vector 29.

### Finding SEC-G07-07 (Low): Empty GCS Backend Prefix & Primitive IAM Roles
- **Location:** `policies/gcp/storage_backend.rego` (Rules 8 and 11)
- **Vulnerability:** 
  1. A Terraform GCS backend configuration with an empty `prefix` (`prefix = ""`) placed state files at the root of the bucket, risking collisions across multiple workspaces or environments.
  2. Storage bucket IAM configurations using overprivileged legacy primitive roles (`roles/owner`, `roles/editor`) were not explicitly blocked.
- **Remediation:**
  1. Added Rule 11 mandating non-empty GCS backend prefix strings.
  2. Added Rule 8 checking and rejecting `roles/owner` and `roles/editor` on storage buckets, enforcing least-privilege roles (e.g. `roles/storage.objectViewer`, `roles/storage.objectUser`).
- **Verification:** Unit tests in `storage_backend_test.rego`, Vector 30, and Section 17.18.

### Finding SEC-G07-08 (Medium): HCL Provider Block Matching False Positives
- **Location:** `policies/gcp/wif_oidc.rego` (`get_providers` helper)
- **Vulnerability:** Conftest loads all policies in `policies/` when evaluating any file. When evaluating AWS configurations (e.g. `examples/aws-reference-module/main.tf`), the block `provider "aws" {}` produced an `input.provider` object. Naive provider extraction matched this object, falsely running GCP WIF rules on the AWS provider block.
- **Remediation:** Added `has_oidc(p)` helper requiring the presence of an `oidc` block (as object or array) before classifying `input.provider` as a GCP Workload Identity Provider.
- **Verification:** Cross-provider verification on AWS reference module (94/94 Conftest tests passed cleanly).

---

## 4. Adversarial Integration Test Matrix (30 Vectors)

The dedicated adversarial integration test suite ([`tests/test_gcp_adversarial_integration.py`](file:///home/tharuka/projects/infraflow/tests/test_gcp_adversarial_integration.py)) implements 30 distinct attack scenarios across three security classes:

| Vector | Threat / Attack Scenario | Security Boundary Evaluated | Expected Outcome | Result |
|:---:|---|---|---|:---:|
| **01** | Valid synthetic GCP configuration | Full adapter pipeline & input guard | Return code 0, all inputs accepted | **PASS** |
| **02** | Invalid GCP Project ID (uppercase, <6 chars, >30 chars, digit start, injection) | Input guard regex validation | Return code 1, error references project-id | **PASS** |
| **03** | Invalid GCP Region (uppercase, underscore, injection) | Input guard regex validation | Return code 1, error references region | **PASS** |
| **04** | Malformed WIF provider resource (non-global location, non-numeric project) | Input guard regex validation | Return code 1, error references provider | **PASS** |
| **05** | Incorrect Service Account email (missing .iam., missing @, injection) | Input guard regex validation | Return code 1, error references SA | **PASS** |
| **06** | Wildcard WIF audience (`*` in provider allowed_audiences) | OPA WIF Rule 2 | Deny triggered: wildcard audience forbidden | **PASS** |
| **07** | Wrong OIDC issuer (untrusted third-party issuer) | OPA WIF Rule 1 | Deny triggered: must be GitHub Actions issuer | **PASS** |
| **08** | Missing owner identity constraint (org-wide owner binding without repository) | OPA WIF Rule 10 | Deny triggered: org-wide access without repo scoping | **PASS** |
| **09** | Repository identity substitution (attempting unauthorized repository) | OPA WIF Rule 5 | Deny triggered: must filter on repository/repository_id | **PASS** |
| **10** | Broad attribute condition (missing repository constraint in CEL) | OPA WIF Rule 5 | Deny triggered: missing mandatory condition | **PASS** |
| **11** | Missing mandatory attribute mapping (missing google.subject or attribute.repository) | OPA WIF Rule 3 | Deny triggered: missing required mapping | **PASS** |
| **12** | Untrusted PR context (`pull_request` event attempting auth - SEC-02) | Input guard SEC-02 invariant | Return code 1, pull request auth rejected | **PASS** |
| **13** | Mutable workflow reference (`@main` instead of 40-character SHA) | Input guard trust boundary | Return code 1, immutable SHA required | **PASS** |
| **14** | Attempted GCP authentication enablement (`enable-gcp-auth: true`) | Input guard simulation invariant | Return code 1, live GCP auth rejected fail-closed | **PASS** |
| **15** | Arbitrary Service Account selection (wildcard `*` in workloadIdentityUser member) | OPA WIF Rule 8 | Deny triggered: wildcard principal prohibited | **PASS** |
| **16** | Malicious backend bucket (`goog*`/`google*`, invalid length, invalid chars) | Input guard bucket naming | Return code 1, reserved prefix / regex failure | **PASS** |
| **17** | Backend prefix traversal (`..` or leading `/`) | Input guard prefix traversal | Return code 1, traversal / leading slash rejected | **PASS** |
| **18** | Public bucket access (`allUsers` / `allAuthenticatedUsers` ACL or public predefined ACL) | OPA Storage Rule 6 | Deny triggered: public bucket ACLs rejected | **PASS** |
| **19** | Public IAM binding (`allUsers` in IAM member/binding on storage bucket) | OPA Storage Rule 7 | Deny triggered: public IAM principal rejected | **PASS** |
| **20** | Missing mandatory storage protection (UBLA=false, PAP=inherited, versioning disabled) | OPA Storage Rules 1, 2, 4 | Deny triggered: UBLA, PAP, versioning enforced | **PASS** |
| **21** | Destructive bucket configuration (`force_destroy = true`) | OPA Storage Rule 5 | Deny triggered: force_destroy prohibited | **PASS** |
| **22** | Malformed or unsupported policy input (syntax error or empty payload handling) | Conftest runtime engine | Handled gracefully without crash or exception | **PASS** |
| **23** | Symlink workspace escape (symlinked working directory or var-file) | Workflow `verify_workspace` | Return code 1, symlink detected and rejected | **PASS** |
| **24** | Shell argument injection (command chaining in parameters) | Input guard regex sanitization | Return code 1, forbidden characters rejected | **PASS** |
| **25** | Missing security job output (summary aggregation with missing inputs) | Summary aggregator | Return code 1, fails closed | **PASS** |
| **26** | Failed job reported as successful (failure propagation in summary) | Summary aggregator | Return code 1, authorization-status: rejected | **PASS** |
| **27** | Unexpected skipped mandatory gate (policy eval or Trivy disabled) | Input guard gate enforcement | Return code 1, disabling gates prohibited | **PASS** |
| **28** | Sensitive input log exposure (zero secret leakage) | Input guard logging audit | Pass, zero credential or secret tokens exposed | **PASS** |
| **29** | Unsafe Terraform state handling (ephemeral plan cleanup trap) | Workflow runtime trap | Pass, POSIX trap removes tfplan & tfplan.json | **PASS** |
| **30** | Cross-environment configuration substitution (empty backend prefix) | OPA Storage Rule 11 | Deny triggered: empty prefix prohibited | **PASS** |

---

## 5. Offline Testing & Mock Provider Limitations

### 5.1 Native Terraform Provider Mocking
The GCP reference module ([`examples/gcp-reference-module/`](file:///home/tharuka/projects/infraflow/examples/gcp-reference-module/)) utilizes Terraform 1.7+ native mock provider syntax:

```hcl
mock_provider "google" {}
```

**Capabilities:**
- Enables offline synthesis, validation, and attribute assertion execution (`terraform test`).
- Verifies module resource graphs without network calls, STS credential requests, or GCP project APIs.
- Guarantees $0.00 cloud spend.

**Limitations:**
- Mock providers do not validate GCP API-side constraints (e.g. active KMS key existence, global bucket name uniqueness, IAM role assignment quotas).
- Complex CEL AST evaluation in OPA is limited to regex and structural string matching rather than dynamic CEL expression execution. Native CEL validation must occur in live GCP Workload Identity Pool APIs during future authenticated execution milestones.

---

## 6. Verification Evidence Summary

| Test Suite / Quality Gate | Executed Command | Tests Run | Result |
|---|---|:---:|:---:|
| **Full Local Validation Harness** | `./scripts/validate-local.sh` | 276 checks | **PASS (276/276)** |
| **Actionlint Workflow Linter** | `actionlint .github/workflows/*.yml` | 5 workflows | **PASS (0 findings)** |
| **Zizmor Supply Chain Auditor** | `zizmor -c .zizmor.yml .github/workflows/reusable-tf-gcp.yml` | 1 workflow | **PASS (0 findings)** |
| **Conftest / OPA Policy Unit Tests** | `conftest verify --policy policies policies` | 128 unit tests | **PASS (128/128)** |
| **Conftest Policy Compliance (AWS)** | `conftest test --all-namespaces -p policies examples/aws-reference-module/main.tf` | 94 policies | **PASS (94/94)** |
| **Conftest Policy Compliance (GCP)** | `conftest test --all-namespaces -p policies examples/gcp-reference-module/main.tf` | 94 policies | **PASS (94/94)** |
| **GCP Adapter Unit Tests** | `python3 -m unittest tests/test_gcp_adapter.py` | 34 tests | **PASS (34/34)** |
| **GCP Adversarial Integration Tests** | `python3 -m unittest tests/test_gcp_adversarial_integration.py` | 30 tests | **PASS (30/30)** |
| **Complete Python Test Suite** | `python3 -m unittest discover tests` | 197 tests | **PASS (197/197)** |
| **GCP Reference Module Native Tests** | `terraform -chdir=examples/gcp-reference-module test` | 1 test run | **PASS (Mock)** |

---

## 7. Conclusion & Next Steps

Milestone **G07.3** has achieved all security hardening, test expansion, discrepancy reconciliation, and regression validation objectives. The platform maintains zero cloud expenditure ($0.00), zero credential leakage, and 100% test pass rates across all 276 quality checks.

**Completed Artifacts:**
- Hardened OPA policies: `policies/gcp/wif_oidc.rego` (19 tests) & `policies/gcp/storage_backend.rego` (20 tests).
- Hardened reusable workflow: `.github/workflows/reusable-tf-gcp.yml` (symlink containment, trap cleanup, gate bypass prevention).
- 30-vector adversarial test suite: `tests/test_gcp_adversarial_integration.py`.
- Expanded local validation harness: `scripts/validate-local.sh` (Section 17 expanded to 26 checks; 276 total checks).
- Architecture & evidence documentation: `docs/evidence/G07/G07-GCP-SECURITY-HARDENING-REPORT.md`.

*Per task instructions, changes remain committed locally to `feature/g07-gcp-adapter` without pushing to remote, merging to `main`, or triggering release tags.*
