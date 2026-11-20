# InfraFlow — Delivery Milestones & Acceptance Criteria

## 1. Program Roadmap Overview

InfraFlow is structured into progressive delivery milestones:

| Milestone | Title | Focus Area | Status |
|---|---|---|---|
| **G01** | **Foundation and Architecture** | Architecture, threat model, repository structure, requirements, adapters spec. | **PASS** |
| **G02** | **Reusable Terraform CI/CD Core** | Reusable `workflow_call` workflow, input validation guard, cloud-free module, tests, negative fixtures. | **PASS** |
| **G03** | **DevSecOps Security Integration** | TFLint static analysis, Trivy IaC scanning, Zizmor workflow security, OPA/Conftest Rego policies. | **PASS** |
| **G04** | **Secure Terraform Planning & Approval Engine** | Speculative plan engine, plan change analysis, OPA live plan evaluation, cryptographic attestation, protected environment approval gate. | **PASS** |
| **G04.1** | **Plan Provenance & Approval Hardening** | Asymmetric DSSE in-toto signed provenance, schema-aware redaction, output masking, ephemeral plan storage. | **PASS** |
| **G04.1.1** | **Trusted Provenance & Human Approval Verification** | Independent trust root, pinned public key, key ID allowlists, key revocation blocklist, 8-scenario approval matrix, 95/95 checks. | **PASS** |
| **G04.1.2** | **Trust Root Isolation & Attack Simulation** | Anti-substitution verification, PR threat analysis, key lifecycle, 12 attack simulation tests, 107/107 checks. | **PASS** |
| **G04.1.3** | **Trusted Workflow Enforcement** | Caller workflow security, trusted configuration, preview/prod signing separation, 10 attack simulation tests, 117/117 checks. | **PASS** |
| **G04.1.4** | **InfraFlow Architecture Finalization** | Governance rulesets, GitHub Artifact Attestations (Sigstore OIDC), automated verified policy gate, dual scanner enforcement, permission boundary isolation, 176/176 checks. | **PASS** |
| **G05** | **AWS Integration** | AWS provider adapter, passwordless Workload Identity Federation (OIDC), S3 state backend. | **PASS** |
| **G06** | **Protected Apply and Destroy** | Secure execution of approved plans with cryptographic digest verification, KMS-encrypted plan storage, and controlled destruction. | **IN PROGRESS (G06.2)** |
| **G07** | **Azure and GCP** | Azure and GCP cloud provider adapters, Workload Identity Federation, cloud state backends. | Backlog (Future) |
| **G08** | **Multi-Repository Adoption** | Fleet-wide rollout, consumer repository templates, centrally controlled organization rulesets. | Backlog (Future) |
| **G09** | **Operational Maturity** | Drift detection, observability, compliance dashboard, automated upgrade campaigns. | Backlog (Future) |

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

## 4. Milestone G03 — Acceptance Criteria (DevSecOps Security Integration)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G03-01** | Trivy IaC Misconfiguration | Trivy integrated to scan Terraform source; rejects insecure configurations with exit code 1; passes secure fixtures. | Automated local & workflow tests | PASS |
| **AC-G03-02** | TFLint Static Analysis | `.tflint.hcl` created with standard rules; catches syntax deprecations and naming violations; blocks on error. | Automated local & workflow tests | PASS |
| **AC-G03-03** | Zizmor Supply Chain Security | Zizmor scans GitHub Actions workflows for excessive permissions, unpinned actions, and injection vectors. | Automated local & workflow tests | PASS |
| **AC-G03-04** | OPA/Conftest Policy as Code | Rego policies in `policies/` (common, aws, azure, gcp); unit tested with `conftest verify`; blocks violations. | `conftest verify` & `conftest test` | PASS |
| **AC-G03-05** | Reusable Security Workflow | `.github/workflows/reusable-tf-security.yml` implemented with minimal tokens, pinned SHAs, and security summary. | `actionlint` & workflow tests | PASS |
| **AC-G03-06** | Negative Security Regression Suite | 8+ negative and positive security regression fixtures verified in automated test suite. | `scripts/validate-local.sh` | PASS |
| **AC-G03-07** | Non-Suppression Governance | Documented false-positive and exception handling without silent suppression. | `docs/security/security-architecture.md` | PASS |
| **AC-G03-08** | Zero Cost & Zero Credentials | All security scanning operates offline with $0 budget and no cloud credentials. | Program invariant audit | PASS |

---

## 5. Milestone G03.1 — Acceptance Criteria (DevSecOps Security Hardening)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G03.1-01** | Zizmor Supply Chain Audit & Hardening | Eliminate blanket file ignore of `ci.yml`. Document parser conflict between Zizmor (`$/...`) and Actionlint. Enforce narrowest rule suppression (`rules.self-repository.ignore: ["ci.yml"]`). All supply chain checks active. | `zizmor` execution on platform workflows & fixtures | PASS |
| **AC-G03.1-02** | Trivy Invariant Audit | Verify zero broad exclusions/ignores. Re-verify exact finding IDs on storage and network fixtures (`AWS-0086`, `AWS-0087`, `AWS-0091`, `AWS-0093`, `AWS-0132`, `AWS-0107`). | Automated fixture scans & exit code checks | PASS |
| **AC-G03.1-03** | TFLint Scope Verification | Verify 8 core rules. Explicitly document provider plugin limitation (offline/$0 invariant) in architecture documentation. | `.tflint.hcl` review & test fixtures | PASS |
| **AC-G03.1-04** | OPA/Conftest Policy Hardening | Prevent attribute omission bypasses via `object.get` and `taggable_resource`. Harden plan evaluation for delete/unknowns. Expand unit tests to 27 tests. | `conftest verify` (27/27 passed) & fixtures | PASS |
| **AC-G03.1-05** | Local Harness Resilience | Eliminate SIGPIPE pipefail termination (`sed -n '1p'`). Execute full 48/48 check regression suite. | `./scripts/validate-local.sh` | PASS |

---

## 6. Milestone G03.2 — Acceptance Criteria (Tagging Correctness & Security Control Deletion)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G03.2-01** | Explicit Metadata Allowlists & Mapping | AWS/Azure `tags` and GCP `labels` mapped via explicit allowlists (`aws_taggable_resources`, etc.); unsupported resources (`aws_route_table_association`, `google_compute_network`) produce zero false positives. | Rego unit tests & HCL fixture scans | PASS |
| **AC-G03.2-02** | Security Control Deletion Protection | Intercept pure deletions of standalone security controls (`aws_s3_bucket_public_access_block`, `azurerm_storage_account_network_rules`, etc.). Block deletion unless parent asset is simultaneously decommissioned. | Plan JSON fixtures & `conftest test` | PASS |
| **AC-G03.2-03** | Replacement Security Enforcement | Evaluate replacement actions (`["delete", "create"]`) against proposed `after` state. Reject replacements that degrade security settings. | Plan JSON fixtures & `conftest test` | PASS |
| **AC-G03.2-04** | Fail-Closed Unknown Attributes | Reject speculative unknown values (`after_unknown`) on security-critical attributes (`acl`, `block_public_acls`, `min_tls_version`, `uniform_bucket_level_access`). | Plan JSON fixtures & `conftest test` | PASS |
| **AC-G03.2-05** | Expanded Regression Suite (56 Checks) | Verify 8 new plan regression fixtures and 55 Rego unit tests. Execute full 56/56 check validation suite. | `./scripts/validate-local.sh` | PASS |

---

## 7. Milestone G03.2.1 — Acceptance Criteria (Replacement Order & Parent Correlation)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G03.2.1-01** | Replacement Action Order Invariance | Enforce security policies identically across both `["delete", "create"]` and `["create", "delete"]`. Reject insecure replacements; allow secure replacements. | Plan JSON fixtures & `conftest test` | PASS |
| **AC-G03.2.1-02** | Exact Parent Deletion Correlation (AWS) | Correlate S3 public access block with exact target bucket and module instance identity (`same_module_scope`). Block deletion if different bucket or different module parent is deleted. | Plan JSON fixtures & `conftest test` | PASS |
| **AC-G03.2.1-03** | Exact Parent Deletion Correlation (Azure) | Correlate Azure storage network rules with exact target storage account and module scope. Block deletion if different storage or different module parent is deleted. | Plan JSON fixtures & `conftest test` | PASS |
| **AC-G03.2.1-04** | Expanded Regression Suite (65 Checks) | Execute 62 native Rego unit tests (`conftest verify`) and 65 quality gates in automated validation harness. | `./scripts/validate-local.sh` | PASS |

---

## 8. Milestone G04 — Acceptance Criteria (Secure Planning & Approval Engine)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G04-01** | Speculative Planning Engine | Generate speculative Terraform plans with `-input=false` and `-lock=false` without cloud credentials; export to JSON via `terraform show -json`. Never execute apply or destroy. | `./scripts/validate-local.sh` & CLI verification | PASS |
| **AC-G04-02** | Plan Analysis Engine | Classify create, update, delete, replace, and no-op changes; extract addresses, types, and computed unknowns; generate sanitized Markdown summary and structured metrics JSON. | `scripts/analyze-plan.py` execution & unit tests | PASS |
| **AC-G04-03** | Sensitive Attribute Protection | Mask passwords, tokens, keys, and credentials with zero plaintext leakage in summaries and metrics. Enforce ephemeral runner temp storage (`chmod 700`) and immediate file cleanup traps. | Fixture test & Gitleaks scan (0 leaks) | PASS |
| **AC-G04-04** | Destructive Change Gating | Classify resource deletions and replacements; support optional hard rejection (`--fail-on-destructive`) with alert diagnostics. | Automated fixture execution | PASS |
| **AC-G04-05** | Cryptographic Plan Attestation | Compute SHA-256 digests of plan files; bind to repository identity, commit SHA, run ID, actor, and Terraform version in `infraflow-plan-attestation-v1` manifest. | `scripts/verify-plan-integrity.py` | PASS |
| **AC-G04-06** | Tampering & Stale Plan Detection | Automated integrity verification rejects altered plan JSON (digest mismatch), stale plans (commit SHA mismatch), and cross-repo spoofing (repository mismatch). | Automated fixture execution | PASS |
| **AC-G04-07** | OPA Policy Gating on Live Plan JSON | Evaluate Conftest/OPA policies against actual generated Terraform plan JSON; enforce tagging, encryption, and deletion safety. | `conftest test` against live plan JSON | PASS |
| **AC-G04-08** | Reusable Workflow Implementation | Implement `.github/workflows/reusable-tf-plan.yml` with least-privilege `permissions: contents: read`, pinned action SHAs, input validation guard, and protected environment approval gate. | `actionlint` & `zizmor` audits | PASS |
| **AC-G04-09** | Protected Environment Approval Gate | Define GitHub Environment `production-approval` with required reviewers; couple manual UI gate with automated cryptographic attestation verification. | Reusable workflow contract & docs | PASS |
| **AC-G04-10** | Comprehensive Local Regression (79 Checks) | Expand local test harness to execute 79 automated quality gates; verify zero regressions across G01–G04. | `./scripts/validate-local.sh` (79/79 passed) | PASS |

---

## 9. Milestone G04.1 — Acceptance Criteria (Plan Provenance & Approval Hardening)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G04.1-01** | Authenticated Digital Provenance Signing | Sign in-toto Statement v1 inside a DSSE envelope (`application/vnd.in-toto+json`) using asymmetric ECDSA (NIST P-256 / SHA-256). Bind binary plan digest, plan JSON digest, repository, commit SHA, run ID, and workflow. | `verify-plan-integrity.py sign-provenance` | PASS |
| **AC-G04.1-02** | Cryptographic Provenance Verification & Forgery Detection | Verify digital signatures using public key; reject altered payloads (`InvalidSignature`), forged signatures, and untrusted public keys. | Automated fixture execution | PASS |
| **AC-G04.1-03** | Environmental & Policy Binding Enforcement | Enforce matching repository (`$GITHUB_REPOSITORY`), commit SHA (`$GITHUB_SHA`), workflow identity, and security policy evaluation outcome (`passed`). | Automated fixture execution | PASS |
| **AC-G04.1-04** | Schema-Aware Sensitive Attribute Redaction | Traverse `before_sensitive` and `after_sensitive` schema trees in `analyze-plan.py`. Recursively redact sensitive maps, lists, and non-obvious attribute keys with zero secret leakage. | Automated fixture & Gitleaks scan | PASS |
| **AC-G04.1-05** | Sensitive Output Redaction | Inspect `output_changes` in plan JSON; mask sensitive outputs to `(sensitive output redacted)` in both Markdown summary and structured metrics JSON. | Automated fixture execution | PASS |
| **AC-G04.1-06** | Approval Gate Bypass Defense | Reject approval bypass attempts including stale source commits, modified candidate plans, missing reviewer authorization, and failed policy results. | Automated fixture execution | PASS |
| **AC-G04.1-07** | Plan Lifecycle & Secure Apply Architecture | Formulate secure retention architecture for future apply without public artifact exposure (KMS envelope encryption & OIDC-authenticated storage). | Documentation review | PASS |
| **AC-G04.1-08** | Full Regression Suite Expansion (91 Checks) | Expand validation harness to 91 automated checks; verify Actionlint, ShellCheck, Zizmor, Conftest, and Gitleaks pass with zero errors. | `./scripts/validate-local.sh` (91/91 passed) | PASS |

---

## 10. Milestone G04.1.1 — Acceptance Criteria (Trusted Provenance & Human Approval Verification)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G04.1.1-01** | Independent Trust Root & Anti-Substitution | Eliminate in-band untrusted public key acceptance; verify signatures against pinned trusted public key (`policies/trust/trusted_signer.pub`) or explicit trusted key ID fingerprint allowlist (`--trusted-keyids`). Reject unpinned keys by default (`--enforce-trusted-signer`). | Automated fixture execution & `./scripts/validate-local.sh` (Tests 10.14-10.16) | PASS |
| **AC-G04.1.1-02** | Private Key Custody & Ephemeral Security | Enforce POSIX mode `600` (`-rw-------`) on private key creation; store ephemeral keys in `${RUNNER_TEMP}`; guarantee zero exposure in git, workflow logs, step outputs, or public artifacts. | Permissions audit & Gitleaks scan (0 leaks) | PASS |
| **AC-G04.1.1-03** | Key Revocation Enforcement | Implement explicit key revocation blocklist (`--revoked-keyids`); reject signatures produced by revoked keys even if present in the allowlist. | Automated fixture execution (Test 10.22) | PASS |
| **AC-G04.1.1-04** | Approval-to-Plan Mathematical Binding | Cryptographically prove that human approval for plan $P_1$ cannot authorize $P_2$; bind candidate plan binary digest, plan JSON digest, and current Git commit SHA to signed provenance statement. | Gate verification (Tests 10.28-10.30) | PASS |
| **AC-G04.1.1-05** | Human Approval Matrix & Operational Truth | Document 8-scenario Human Approval Verification Matrix; accurately classify Scenarios 1–5 as UNVERIFIED (requiring live GitHub Environment configuration) and Scenarios 6–8 as PASS (cryptographic binding). Correct false equivalence between cryptographic rejection and human review. | `docs/planning/approval-model.md` & `verification-report.md` | PASS |
| **AC-G04.1.1-06** | Full Regression Suite Expansion (95 Checks) | Expand automated quality gates to 95 checks; verify zero regressions across G01–G04.1.1 with zero Actionlint errors, zero Zizmor findings, zero ShellCheck warnings, and zero Gitleaks findings. | `./scripts/validate-local.sh` (95/95 passed) | PASS |

---

## 11. Milestone G04.1.2 — Acceptance Criteria (Trust Root Isolation & Attack Simulation)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G04.1.2-01** | Trust Root Isolation Architecture | Evaluate PR threat vectors; guarantee verifier cannot be subverted by PR modifications to public keys, allowlists, or scripts. Enforce Platform Trust Anchor (`3c27ef...`) and toolchain isolation. | Codebase inspection & test suite | PASS |
| **AC-G04.1.2-02** | Anti-Substitution Key Verification | Verifier checks public key files from disk against trusted allowlists; rejects attacker public key files substituted on disk even if validly signed. | `./scripts/validate-local.sh` (Test 11.1) | PASS |
| **AC-G04.1.2-03** | Twelve-Scenario Attack Simulation Suite | Execute automated negative attack simulation suite covering PR public key replacement, allowlist tampering, script alteration, workflow modification, self-signed keys, revocation, wrong repo, wrong workflow, binary tampering, JSON tampering, provenance alteration, and stale commits. Every scenario fails closed. | `./scripts/validate-local.sh` (Tests 11.1–11.12) | PASS |
| **AC-G04.1.2-04** | Cryptographic Key Provisioning Architecture | Formally define key provisioning lifecycle: distinguish persistent protected signing key, temporary runner copy, ephemeral signing identity, and public trust anchor. Document generation, storage, rotation, revocation, and disaster recovery. | `docs/planning/plan-security.md` | PASS |
| **AC-G04.1.2-05** | Branch Protection Governance Truth | Rigorously separate local branch-guard tests from remote GitHub branch protection configuration; classify remote branch protection as UNVERIFIED without live SaaS account. | `docs/planning/approval-model.md` & `verification-report.md` | PASS |
| **AC-G04.1.2-06** | Full Regression Expansion (107 Checks) | Expand automated validation harness to 107 quality gates; verify zero regressions across G01–G04.1.2 with zero Actionlint errors, zero Zizmor findings, zero ShellCheck warnings, zero Gitleaks leaks, and 62/62 passing OPA tests. | `./scripts/validate-local.sh` (107/107 passed) | PASS |

---

## 12. Milestone G04.1.3 — Acceptance Criteria (Trusted Workflow Enforcement)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G04.1.3-01** | Caller Workflow Security & Protection | Prove that pinning reusable workflows alone does not protect callers; articulate Organization Required Workflows and Branch Protection Status Check enforcement. Ensure untrusted PRs never execute with privileged credentials. | Architecture review & test suite | PASS |
| **AC-G04.1.3-02** | Trusted Configuration Architecture | Guarantee that trusted signers, revocations, expected repo, expected workflow, production authorization, and approval requirements cannot be controlled by untrusted PR inputs. Retrieve from protected sources. | `./scripts/validate-local.sh` (Tests 12.3–12.8) | PASS |
| **AC-G04.1.3-03** | Signing Identity Separation | Implement strict cryptographic separation between preview and production signing tiers (`signing_tier: preview` vs `production`). Enforce that ephemeral preview keys cannot authorize production deployments (`--require-production-signer`). | `./scripts/validate-local.sh` (Test 12.9) | PASS |
| **AC-G04.1.3-04** | Ten-Scenario Trusted Workflow Attack Suite | Execute automated negative attack suite: security workflow removal, workflow SHA tampering, attacker fingerprint injection, trusted key modification, revocation omission, verifier replacement, approval environment removal, repo spoofing, preview signer bypass, and missing security check authorization. All fail closed. | `./scripts/validate-local.sh` (Tests 12.1–12.10) | PASS |
| **AC-G04.1.3-05** | Remote Ruleset & Branch Protection Truth | Rigorously separate local workflow guard tests from remote GitHub Organization Rulesets and Branch Protection; classify remote rulesets as UNVERIFIED without live SaaS account. | `docs/planning/approval-model.md` & `verification-report.md` | PASS |
| **AC-G04.1.3-06** | Full Regression Suite Expansion (117 Checks) | Expand automated quality gates to 117 checks; verify zero regressions across G01–G04.1.3 with zero Actionlint errors, zero Zizmor findings, zero ShellCheck warnings, zero Gitleaks leaks, and 62/62 passing OPA tests. | `./scripts/validate-local.sh` (117/117 passed) | PASS |

---

## 13. Milestone G04.1.4 — Acceptance Criteria (InfraFlow Architecture Finalization)

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G04.1.4-01** | Repository Governance Rulesets (Decision 1) | Formalize repository-level GitHub Rulesets ([.github/rulesets/main-ruleset.json](file:///home/tharuka/projects/infraflow/.github/rulesets/main-ruleset.json)) for personal, public InfraFlow repos. Require PRs, stale review dismissals, strict branch updates, GitHub Actions check source, sensitive file restrictions, force push blocks, and zero bypass actors. Document enterprise organization-level adoption ($0 budget preserved). | Schema validation & `./scripts/validate-local.sh` (Tests 13.1–13.6) | PASS |
| **AC-G04.1.4-02** | GitHub Artifact Attestations (Decision 2) | Adopt GitHub Artifact Attestations (`actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2`) with Sigstore OIDC as the authoritative production provenance architecture. Generate and attest sanitized `plan-manifest.json` binding binary and JSON plan digests, repo, commit, run ID, and security decision (`passed`). Rejects long-lived keys in GitHub Secrets. | `./scripts/validate-local.sh` (Tests 13.7, 13.8, 13.13) | PASS |
| **AC-G04.1.4-03** | Verified Policy Gate Attestation Enforcement | Verified policy gate strictly verifies Sigstore attestation bundle and manifest using `verify-attestation`. Fails closed on tampered manifests, cross-repo spoofing, failed security decisions, or missing production attestations. | `./scripts/validate-local.sh` (Tests 13.9–13.12, 14.19–14.26) | PASS |
| **AC-G04.1.4-04** | Legacy Decoupling & Offline Compatibility | Retain asymmetric ECDSA signing exclusively for offline unit testing and backwards compatibility. Strictly prohibit ECDSA keys from serving as the default production trust identity. | `./scripts/validate-local.sh` (Test 13.12) | PASS |
| **AC-G04.1.4-05** | Solo-Engineer Automated Governance Gate (Decision 3) | Refactor human approval gate into an automated Verified Policy Gate (`verified-policy-gate`) for solo-engineer portfolio governance. Document operational truth: machine policy and cryptographic verification = PASS, human review = inactive / not implemented in solo context, production apply = out of scope (G06). | `docs/planning/approval-model.md` & `verification-report.md` | PASS |
| **AC-G04.1.4-06** | Full Regression Suite Expansion (176 Checks) | Expand validation suite to 176 quality gates (including job permission isolation, dual-scanner enforcement, platform severity invariance, and immutable OPA policy protection); verify zero regressions across G01–G04.1.4 with zero Actionlint errors, zero Zizmor findings, zero ShellCheck warnings, zero Gitleaks leaks, and 62/62 passing OPA tests. | `./scripts/validate-local.sh` (176/176 passed) | PASS |
| **AC-G04.1.4-07** | Platform Trust-Boundary Hardening (183 Checks) | Remove caller-controlled `platform-repository` and `platform-ref` inputs from both reusable workflows. Establish trusted platform identity via `github.workflow_repository` and `github.workflow_sha`. Hardcode attestation signer identity in `verify-plan-integrity.py` verification step. Add 7 trust-boundary regression tests (14.45–14.51). Expand validation suite to 183 quality gates. | `./scripts/validate-local.sh` (183/183 passed) | PASS |

---

## 14. Milestone G05 — Acceptance Criteria (AWS Integration)

Milestone G05 extends InfraFlow with Tier 2 cloud provider adapters, establishing passwordless AWS Workload Identity Federation (OIDC) and Amazon S3 remote state management with native lockfiles.

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G05-01** | AWS Adapter Interface & Contract | Design and implement `.github/workflows/reusable-tf-aws.yml` reusable workflow contract accepting `aws-region`, `role-to-assume`, `backend-bucket`, `backend-key`, `terraform-version`, `environment`, and optional `backend-dynamodb-table`. Enforce universal adapter contract with clean separation between cloud-free PR checks and authenticated cloud planning. | Architecture audit & `actionlint` | **PASS (G05.2 Implemented)** |
| **AC-G05-02** | OIDC Identity & IAM Trust Policy as Code | Implement and enforce OPA Policy-as-Code rules ([`policies/aws/iam_oidc.rego`](file:///home/tharuka/projects/infraflow/policies/aws/iam_oidc.rego)) auditing AWS IAM trust policies. Enforce `sts:AssumeRoleWithWebIdentity`, `StringEquals` audience matching `sts.amazonaws.com`, and strict repository scoping supporting post-July 15, 2026 immutable IDs (`repo:OWNER@ID/REPO@ID:...`) and legacy names (`repo:OWNER/REPO:...`). Strictly reject open wildcards (`*`, `repo:*`, `repo:*:*`, `repo:<org>/*:*`) and untrusted pull request triggers. | Unit test execution (`conftest verify`) — 27/27 tests passed | **PASS (G05.1 Implemented & G05.2 Updated)** |
| **AC-G05-03** | Permission Isolation & Least Privilege | Restrict `id-token: write` token elevation strictly to protected branches/environments at the job level. Prohibit cloud credentials during untrusted pull request execution (`SEC-02`). Enforce read-only IAM planning roles (`s3:GetObject` on state, `s3:PutObject`/`DeleteObject` strictly on `*.tflock`) with permission boundaries. | Architecture specification & reusable workflow jobs | **PASS (G05.2 Implemented)** |
| **AC-G05-04** | S3 Backend & Native State Locking (`use_lockfile`) | Establish Amazon S3 remote state architecture with SSE-KMS / AES256 encryption, bucket versioning, and public access blocks. Adopt native S3 state locking via S3 Conditional Writes (`use_lockfile = true`) for Terraform >= 1.10.x, eliminating mandatory DynamoDB tables. Retain DynamoDB solely for optional legacy compatibility. | Dynamic backend engine in `reusable-tf-aws.yml` | **PASS (G05.2 Implemented)** |
| **AC-G05-05** | Secure Input Sanitization & Parameter Validation | Implement defensive bash guard validating inputs: Role ARN regex (`^arn:aws:iam::[0-9]{12}:role/...`), AWS region allowlist regex (`^[a-z]{2}-[a-z]+-[0-9]+$`), S3 bucket naming regex, relative state keys (blocking `..` traversal), and SemVer `>= 1.6.0`. | Automated fixture execution (Section 15 Quality Gates) | **PASS (G05.2 Implemented)** |
| **AC-G05-06** | AWS Reference Module & Consumer Workflow Example | Provide an exemplary AWS reference Terraform module (`examples/aws-reference-module/`) with native unit tests (`.tftest.hcl` using mock provider) and a sample consumer workflow demonstrating compliant AWS integration. | Module and workflow implementation & tests | **PASS (G05.2 Implemented)** |
| **AC-G05-07** | Offline Testing Harness & Regression Prevention | Expand local validation harness (`scripts/validate-local.sh`) with Section 15 AWS quality gates (negative input tests, mock backend tests, actionlint, and OIDC policy tests) without requiring AWS accounts or cloud spend ($0.00). Ensure zero regressions in G01-G04. | `scripts/validate-local.sh` execution | **PASS (G05.2 Implemented)** |
| **AC-G05-08** | External Consumer Integration & Release Evidence | Verify integration in external consumer repository (`TM-threemavithana/infraflow-consumer-test`), execute adversarial trust boundary tests, author evidence report, and release platform version `v0.3.0`. | Live CI execution & adversarial test report | **PASS** |

---

## 15. Milestone G06 — Acceptance Criteria (Protected Apply and Destroy)

Milestone G06 enables secure, state-modifying Terraform application and destruction governed by cryptographic digest verification, client-side KMS envelope encryption, and fail-closed state consistency.

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G06-01** | Plan Envelope Encryption Engine | Implement client-side AES-256-GCM envelope encryption for Terraform binary plans with fresh 256-bit DEK, 96-bit nonce, canonical AAD context binding, and SHA-256 plan digest binding in `scripts/kms-envelope.py`. | Automated unit test suite (`tests/test_kms_envelope.py`) | **PASS (G06.1 Implemented)** |
| **AC-G06-02** | Offline Mock KMS Simulator | Implement local Key Encryption Key (KEK) simulator modeling AWS KMS `GenerateDataKey` and `Decrypt` interfaces under AES-256-GCM. Reject wrong keys, context mismatches, and tampered wrapped DEKs. | Automated unit test suite (`tests/test_kms_envelope.py`) | **PASS (G06.1 Implemented)** |
| **AC-G06-03** | Pre-Apply Cryptographic Verification | Implement pre-apply gate downloading encrypted plan, unwrapping DEK, recomputing SHA-256 digest, and strictly matching against attested `plan-manifest.json` before invoking `terraform apply`. | Automated adversarial fixture execution | **PASS (G06.2 Implemented)** |
| **AC-G06-04** | Plan Freshness & TTL Enforcement | Enforce configurable plan time-to-live (default max 12 hours). Fails closed if plan timestamp exceeds allowable expiration threshold. | Automated fixture execution with expired timestamps | **PASS (G06.2 Implemented)** |
| **AC-G06-05** | State Consistency & Replay Prevention | Inspect remote state serial and lineage at apply time against planning metadata. Maintain plan execution ledger to prevent re-applying executed plans. | Simulated state drift & replay attack fixtures | **PASS (G06.2 Implemented)** |
| **AC-G06-06** | Reusable Apply Workflow Contract | Implement `.github/workflows/reusable-tf-apply.yml` with `workflow_call`, input guards, environment binding, and zero credentials in PRs. | `actionlint`, `zizmor`, and local workflow tests | **PLANNED (G06.3 Scope)** |
| **AC-G06-07** | Least-Privilege Credential Separation | Separate IAM Planning Role (read-only state) from IAM Apply Role (state-modifying). Ensure apply role cannot be assumed from PRs. | Rego OIDC policy tests & workflow AST audit | **PLANNED (G06.3 Scope)** |
| **AC-G06-08** | Controlled Destruction & Blast Radius | Implement blast-radius threshold (`max-deletions`) and require explicit confirmation input (`destroy-confirmation-token`) for full destruction. | Negative test fixtures with unconfirmed destroy | **PLANNED (G06.4 Scope)** |
| **AC-G06-09** | State Locking & Fail-Safe Cleanup | Implement exclusive write-lock acquisition with POSIX exit trap ensuring lock release on success, error, or job cancellation. | Simulated crash test verifying lock release | **PLANNED (G06.4 Scope)** |
| **AC-G06-10** | Offline Local Regression Suite (230+ Checks) | Expand `scripts/validate-local.sh` to include all G06 quality gates without cloud spend ($0.00). Ensure zero regressions in G01–G05. | Complete execution of `scripts/validate-local.sh` | **PLANNED (G06.5 Scope)** |

---

## 16. Quality Gate Definitions

To achieve status **PASS** for G01 and G02:
1. Every G01 document must exist, be fully elaborated, and be internally consistent.
2. The reusable workflow and caller example must pass `actionlint` without errors or warnings.
3. The cloud-free Terraform module must pass format check, validation, and all unit test assertions.
4. All negative test fixtures must fail as expected with appropriate error codes.
5. The local validation runner script must complete with exit code 0.
6. Git status must remain clean of untracked temporary files.
7. Any capability not executable locally (e.g. live GitHub-hosted cross-repository call) must be transparently designated **NOT TESTED**.
