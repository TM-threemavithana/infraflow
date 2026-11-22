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
| **G06** | **Protected Apply and Destroy (Simulation Scope)** | Secure execution simulation of approved plans with cryptographic digest verification, KMS envelope encryption, state consistency, blast-radius safeguards, and adversarial validation. | **PASS (Simulation Scope)** |
| **G07** | **Azure and GCP** | Azure and GCP cloud provider adapters, Workload Identity Federation, cloud state backends. | **PASS (Completed)** |
| **G08** | **Multi-Repository Adoption** | Fleet-wide rollout, consumer repository templates, onboarding contracts, centralized governance, fleet upgrade orchestration, and release v0.6.0. | **PASS (Completed)** |
| **G09** | **Operational Maturity** | Drift detection, observability, compliance dashboard, automated upgrade campaigns, and release v0.7.0. | **PASS (Completed)** |
| **G10.1** | **Unified Platform CLI & Diagnostics** | Unified `infraflow` CLI, environment doctor (12 dimensions), drift runner, upgrade manager, policy error enrichment. | **PASS (Completed)** |
| **G10.2** | **Self-Service Onboarding & Scaffolding** | Self-service `infraflow init`, multi-cloud templates, schema-validated registration, dry-run safety. | **PASS (Completed)** |
| **G10.3** | **Consumer Secret Defense & Semantic Destruction** | Mandatory secret scanner, zero raw leakage, multi-cloud critical resource protection, replacement safety, conftest gates. | **PASS (Completed)** |
| **G10.3.1** | **Security Integration Assurance & Decommission Hardening** | Multi-workflow secret scanning, Conftest all-namespaces evaluation, decommission bypass closure, 16-test suite, 455/455 checks. | **PASS (Completed)** |

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

## 15. Milestone G06 — Acceptance Criteria (Protected Apply and Destroy — Simulation Scope)

Milestone G06 establishes a protected pre-execution simulation engine for Terraform binary plans governed by cryptographic digest verification, client-side KMS envelope encryption, fail-closed state consistency, and blast-radius destruction safeguards. All validation is conducted in simulation mode ($0.00 cloud spend, zero live credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G06-01** | Plan Envelope Encryption Engine | Implement client-side AES-256-GCM envelope encryption for Terraform binary plans with fresh 256-bit DEK, 96-bit nonce, canonical AAD context binding, and SHA-256 plan digest binding in `scripts/kms-envelope.py`. | Automated unit test suite (`tests/test_kms_envelope.py`) | **PASS (G06.1 Implemented)** |
| **AC-G06-02** | Offline Mock KMS Simulator | Implement local Key Encryption Key (KEK) simulator modeling AWS KMS `GenerateDataKey` and `Decrypt` interfaces under AES-256-GCM. Reject wrong keys, context mismatches, and tampered wrapped DEKs. | Automated unit test suite (`tests/test_kms_envelope.py`) | **PASS (G06.1 Implemented)** |
| **AC-G06-03** | Pre-Apply Cryptographic Verification | Implement pre-apply gate downloading encrypted plan, unwrapping DEK, recomputing SHA-256 digest, and strictly matching against attested `plan-manifest.json` before invoking simulation. | Automated adversarial fixture execution | **PASS (G06.2 Implemented)** |
| **AC-G06-04** | Plan Freshness & TTL Enforcement | Enforce configurable plan time-to-live (default max 12 hours). Fails closed if plan timestamp exceeds allowable expiration threshold. | Automated fixture execution with expired timestamps | **PASS (G06.2 Implemented)** |
| **AC-G06-05** | State Consistency & Replay Prevention | Inspect remote state serial and lineage at apply time against planning metadata. Maintain plan execution ledger to prevent re-applying executed plans. | Simulated state drift & replay attack fixtures | **PASS (G06.2 Implemented)** |
| **AC-G06-06** | Reusable Apply Workflow Contract | Implement `.github/workflows/reusable-tf-apply.yml` with `workflow_call`, input guards, environment binding, and zero credentials in PRs. | `actionlint`, `zizmor`, and local workflow tests | **PASS (G06.3 Implemented)** |
| **AC-G06-07** | Simulation Authorization Contract | Emit 8 standardized contract outputs with `authorization-status=AUTHORIZED_FOR_SIMULATION` and `simulation-status=simulated-only`. Rejects untrusted pull requests. | Automated workflow contract tests (`tests/test_apply_workflow.py`) | **PASS (G06.3 Implemented)** |
| **AC-G06-08** | Controlled Destruction & Blast Radius | Implement blast-radius thresholds (max deletions and replacements), security-critical asset protections (IAM, KMS, S3 perimeters), and require cryptographically bound confirmation contract (`infraflow-destruction-confirmation-v1`) for destructive changes. | Adversarial unit test suite (`tests/test_destruction_recovery.py`) & local validation harness (Tests 16.27–16.34) | **PASS (G06.4 Implemented)** |
| **AC-G06-09** | State Locking & Fail-Safe Cleanup | Implement execution recovery state machine with crash containment, non-retryable `OUTCOME_UNCERTAIN` state lock, prohibition of automatic rollbacks, and POSIX cleanup traps with mode 0600 file permissions. | Adversarial unit test suite (`tests/test_destruction_recovery.py`) & local validation harness | **PASS (G06.4 Implemented)** |
| **AC-G06-10** | Offline Local Regression Suite (250 Checks) | Expand `scripts/validate-local.sh` to include all G06 quality gates (133 Python tests, 89 OPA tests, 250 local checks) without cloud spend ($0.00). Ensure zero regressions in G01–G05. | Complete execution of `scripts/validate-local.sh` (250/250 PASS) | **PASS (G06.5 Implemented)** |
| **AC-G06-11** | Independent Adversarial Security Validation | Conduct red-team adversarial evaluation across attack classes A, B, C, D. Remediate 6 verified security findings (SEC-ADV-01 through SEC-ADV-06). | 39-test adversarial integration suite (`tests/test_g06_adversarial_integration.py`) | **PASS (G06.5 Implemented)** |
| **AC-G06-12** | External Consumer Integration & Release | Execute end-to-end positive simulation, 12-vector negative adversarial matrix, and SEC-02 PR rejection on independent consumer repository (`TM-threemavithana/infraflow-consumer-test`). Publish release `v0.4.0`. | Live GitHub Actions CI execution & evidence report | **PASS (G06.6 Implemented)** |

---

## 16. Milestone G07.2 — Acceptance Criteria (Google Cloud Adapter & Workload Identity Foundation)

Milestone G07.2 implements the foundation of the Google Cloud Platform (GCP) adapter, establishing passwordless Workload Identity Federation (WIF) OIDC security policies, secure GCS backend contracts, an offline speculative plan reusable workflow, and native mock-provider testing without requiring a GCP account, credentials, or paid cloud infrastructure ($0.00 spend).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G07-01** | Multi-Cloud Architectural Assessment | Produce comprehensive multi-cloud readiness assessment evaluating Azure and GCP Workload Identity Federation trust models, remote backend contracts, and reusable workflow architecture. | Architectural document (`docs/architecture/G07-MULTICLOUD-READINESS-ASSESSMENT.md`) | **PASS (G07.1 Completed)** |
| **AC-G07-02** | Workload Identity Federation OIDC Policies as Code | Implement OPA Rego policies ([`policies/gcp/wif_oidc.rego`](file:///home/tharuka/projects/infraflow/policies/gcp/wif_oidc.rego)) enforcing GitHub Actions issuer URI, explicit provider audience URIs (blocking `*`), mandatory attribute mappings (`google.subject`, `attribute.repository`), mandatory attribute conditions (blocking wildcard repository access), and strict `principalSet` Service Account IAM bindings. | Unit test execution (`conftest verify`) — 18/18 tests passed | **PASS (G07.2 Implemented)** |
| **AC-G07-03** | GCS State Backend Security Contract as Code | Implement OPA Rego policies ([`policies/gcp/storage_backend.rego`](file:///home/tharuka/projects/infraflow/policies/gcp/storage_backend.rego)) enforcing Uniform Bucket-Level Access (CIS GCP 5.2), Public Access Prevention (`enforced`, CIS GCP 5.1), Object Versioning, `force_destroy = false`, CMEK Cloud KMS key format validation, and complete rejection of public ACLs and public IAM members (`allUsers`, `allAuthenticatedUsers`). | Unit test execution (`conftest verify`) — 16/16 tests passed | **PASS (G07.2 Implemented)** |
| **AC-G07-04** | Reusable GCP Workflow Contract (`reusable-tf-gcp.yml`) | Implement `.github/workflows/reusable-tf-gcp.yml` with strict regex input guards, immutable SHA caller verification, fail-closed live authentication rejection (`enable-gcp-auth: true` blocked in G07.2 simulation), speculative cloud-free planning (`terraform init -backend=false`), dual security scanning (Trivy + Conftest), and standardized 7-output contract. | `actionlint`, `zizmor` (0 findings), and workflow unit tests | **PASS (G07.2 Implemented)** |
| **AC-G07-05** | GCP Reference Module & Mock Provider Testing | Implement `examples/gcp-reference-module/` with Terraform `>= 1.7.0` provider mocking (`mock_provider "google" {}` in `tests/gcs_test.tftest.hcl`), full policy compliance (UBLA, PAP, CMEK, mandatory labels), and zero credential requirement. | `terraform fmt`, `init -backend=false`, `validate`, `test` | **PASS (G07.2 Implemented)** |
| **AC-G07-06** | Dedicated GCP Python Test Suite | Implement comprehensive unit test suite ([`tests/test_gcp_adapter.py`](file:///home/tharuka/projects/infraflow/tests/test_gcp_adapter.py)) covering project ID, region, WIF provider, SA email, and bucket regexes, extracted bash guard execution, summary failure propagation, and module structure. | `python3 -m unittest discover tests` — 29/29 tests passed (162 total suite passed) | **PASS (G07.2 Implemented)** |
| **AC-G07-07** | Local Validation Harness Expansion (272 Checks) | Expand `scripts/validate-local.sh` with Section 17 GCP quality gates (22 new checks, including Actionlint, Zizmor, Conftest verify, 12 negative input tests, reference module tests, Trivy, and test suite). Verify 100% offline ($0.00 cloud spend) with zero regressions across G01–G06. | `scripts/validate-local.sh` execution (272/272 PASS) | **PASS (G07.2 Implemented)** |
| **AC-G07-08** | GCP Implementation & Architecture Documentation | Author comprehensive implementation and security guide ([`docs/adapters/gcp-adapter-guide.md`](file:///home/tharuka/projects/infraflow/docs/adapters/gcp-adapter-guide.md)) and update architectural specifications ([`docs/architecture/ADAPTERS.md`](file:///home/tharuka/projects/infraflow/docs/architecture/ADAPTERS.md)). | Documentation audit and link verification | **PASS (G07.2 Implemented)** |

---

## 17. Milestone G07.3 — Acceptance Criteria (GCP Adapter Security Hardening & Offline Validation)

Milestone G07.3 executes comprehensive security hardening, OPA discrepancy reconciliation, adversarial integration testing, and full offline regression verification of the Google Cloud Platform (GCP) adapter ($0.00 cloud spend, zero credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G07-09** | OPA Policy Test Count Reconciliation & Expansion | Reconcile the G06-to-G07.2 policy count discrepancy (unifying 89 baseline + 42 GCP tests = 128 total Rego unit tests) across `policies/gcp/wif_oidc_test.rego` (19 tests) and `policies/gcp/storage_backend_test.rego` (20 tests). | Automated conftest verification (`conftest verify`) — 128/128 tests passed | **PASS (G07.3 Implemented)** |
| **AC-G07-10** | Workload Identity Federation (WIF) Policy Hardening | Harden WIF Rego policy ([`policies/gcp/wif_oidc.rego`](file:///home/tharuka/projects/infraflow/policies/gcp/wif_oidc.rego)) to inspect `members` arrays for org-wide owner bypasses (Rule 10), reject pull request ref conditions (Rule 6), enforce global pool format (Rule 9), and support immutable repository IDs. | Automated unit tests and adversarial vectors 6–11 | **PASS (G07.3 Implemented)** |
| **AC-G07-11** | GCS State Backend Security Hardening | Harden GCS storage policies ([`policies/gcp/storage_backend.rego`](file:///home/tharuka/projects/infraflow/policies/gcp/storage_backend.rego)) enforcing non-empty `prefix` (Rule 11), rejecting primitive IAM roles (`roles/owner`, `roles/editor`, Rule 8), and blocking public ACL and IAM bindings (`allUsers`, `allAuthenticatedUsers`). | Automated unit tests and adversarial vectors 18–21, 30 | **PASS (G07.3 Implemented)** |
| **AC-G07-12** | Reusable Workflow Security Hardening | Harden `.github/workflows/reusable-tf-gcp.yml` with `policy-directory` input sanitization, fatal rejection of mandatory security gate bypasses (`enable-policy-evaluation: false` / `enable-trivy: false`), workspace symlink containment (`verify_workspace`), and unencrypted plan cleanup traps (`trap 'rm -f tfplan tfplan.json'`). | `actionlint`, `zizmor` (0 findings), and adversarial vectors 23, 27, 29 | **PASS (G07.3 Implemented)** |
| **AC-G07-13** | Dedicated 30-Vector Adversarial Integration Suite | Author comprehensive 30-vector adversarial suite ([`tests/test_gcp_adversarial_integration.py`](file:///home/tharuka/projects/infraflow/tests/test_gcp_adversarial_integration.py)) covering identity substitution, CEL condition manipulation, audience wildcards, storage tampering, symlink escapes, and failure propagation. | `python3 -m unittest tests/test_gcp_adversarial_integration.py` (30/30 passed) | **PASS (G07.3 Implemented)** |
| **AC-G07-14** | Offline Local Regression Harness Expansion (276 Checks) | Expand Section 17 of `scripts/validate-local.sh` to 26 dedicated GCP checks (increasing total platform checks from 272 to 276). Verify 100% offline ($0.00 cloud spend) with zero regressions across G01–G06. | `scripts/validate-local.sh` execution (276/276 PASS) | **PASS (G07.3 Implemented)** |
| **AC-G07-15** | Adversarial Evidence & Hardening Documentation | Produce comprehensive security audit and adversarial report ([`docs/evidence/G07/G07-GCP-SECURITY-HARDENING-REPORT.md`](file:///home/tharuka/projects/infraflow/docs/evidence/G07/G07-GCP-SECURITY-HARDENING-REPORT.md)) detailing threat model analysis, vulnerability remediation, and test matrices. | Documentation audit and link verification | **PASS (G07.3 Implemented)** |

---

## 18. Milestone G07.5 — Acceptance Criteria (Microsoft Azure Adapter & Workload Identity Foundation)

Milestone G07.5 implements the foundation of the Microsoft Azure adapter, establishing passwordless Microsoft Entra ID Workload Identity Federation (WIF) OIDC security policies, secure Azure Blob Storage remote backend contracts, an offline speculative plan reusable workflow, and native mock-provider testing without requiring an Azure account, subscription, credentials, or paid cloud infrastructure ($0.00 spend).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G07-16** | Microsoft Entra ID OIDC Federation Policies as Code | Implement OPA Rego policies ([`policies/azure/entra_oidc.rego`](file:///home/tharuka/projects/infraflow/policies/azure/entra_oidc.rego)) enforcing GitHub Actions issuer URI, explicit audience (`api://AzureADTokenExchange`), exact subject claim formats (standard branch, standard environment, and immutable repository ID post-July 15, 2026), complete rejection of wildcard subjects (`*`), SEC-02 pull request rejection, UUID format constraints, parent identity binding, and least-privilege RBAC. | Unit test execution (`conftest verify`) — 18/18 tests passed | **PASS (G07.5 Implemented)** |
| **AC-G07-17** | Azure Blob Storage Backend Security Contract as Code | Implement OPA Rego policies ([`policies/azure/storage_backend.rego`](file:///home/tharuka/projects/infraflow/policies/azure/storage_backend.rego)) enforcing resource group, storage account, and container naming rules, state key path traversal defense, mandatory Microsoft Entra ID data-plane authentication (`use_azuread_auth` or `use_oidc`), prohibition of static access keys, private container access, minimum TLS 1.2, network restrictions, encryption, blob versioning, and environment namespace isolation. | Unit test execution (`conftest verify`) — 18/18 tests passed | **PASS (G07.5 Implemented)** |
| **AC-G07-18** | Reusable Azure Workflow Contract (`reusable-tf-azure.yml`) | Implement `.github/workflows/reusable-tf-azure.yml` with strict regex and UUIDv4 input guards, aliased input support (`backend-resource-group`, `backend-storage-account`, etc.), immutable SHA caller verification, fail-closed live authentication rejection (`enable-azure-auth: true` blocked in G07.5 simulation), speculative cloud-free planning (`terraform init -backend=false`), dual security scanning (Trivy + Conftest), and standardized 7-output contract with plan metrics extraction and summary aggregator. | `actionlint`, `zizmor` (0 findings), and workflow unit tests | **PASS (G07.5 Implemented)** |
| **AC-G07-19** | Azure Reference Module & Mock Provider Testing | Implement `examples/azure-reference-module/` with Terraform `>= 1.7.0` provider mocking (`mock_provider "azurerm" {}` in `tests/azure_test.tftest.hcl`), full policy compliance (private container, network rules, TLS 1.2, versioning, infrastructure encryption, mandatory tags), and zero credential requirement. | `terraform fmt`, `init -backend=false`, `validate`, `test` | **PASS (G07.5 Implemented)** |
| **AC-G07-20** | Dedicated Azure Python Test Suite | Implement comprehensive unit test suite ([`tests/test_azure_adapter.py`](file:///home/tharuka/projects/infraflow/tests/test_azure_adapter.py)) with 39 unit and adversarial tests covering UUIDv4, resource group, storage account, container, and region regexes, extracted bash guard execution, summary failure propagation, and reference module configuration. | `python3 -m unittest tests/test_azure_adapter.py` — 39/39 tests passed | **PASS (G07.5 Implemented)** |
| **AC-G07-21** | Local Validation Harness Expansion (302 Checks) | Expand `scripts/validate-local.sh` with Section 18 Azure quality gates (25 new checks, including Actionlint, Zizmor, Conftest verify, 13 negative input and security tests, reference module tests, Trivy, and test suite). Verify 100% offline ($0.00 cloud spend) with zero regressions across G01–G07.4. | `scripts/validate-local.sh` execution (302/302 PASS) | **PASS (G07.5 Implemented)** |
| **AC-G07-22** | Azure Implementation & Architecture Documentation | Author comprehensive implementation and security guide ([`docs/adapters/azure-adapter-guide.md`](file:///home/tharuka/projects/infraflow/docs/adapters/azure-adapter-guide.md)) and update architectural specifications ([`docs/architecture/ADAPTERS.md`](file:///home/tharuka/projects/infraflow/docs/architecture/ADAPTERS.md) and [`docs/architecture/MILESTONES.md`](file:///home/tharuka/projects/infraflow/docs/architecture/MILESTONES.md)). | Documentation audit and link verification | **PASS (G07.5 Implemented)** |

---

## 19. Milestone G07.6 — Acceptance Criteria (Azure Adapter Security Hardening & Adversarial Validation)

Milestone G07.6 executes comprehensive security hardening, adversarial integration testing, and offline regression verification of the Microsoft Azure adapter ($0.00 cloud spend, zero credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G07-23** | Microsoft Entra ID OIDC Policy Hardening | Harden Entra ID policy ([`policies/azure/entra_oidc.rego`](file:///home/tharuka/projects/infraflow/policies/azure/entra_oidc.rego)) with Rule 6 expected repository & repository ID matching, Rule 6.1 flexible FIC custom claims rejection, and RFC 4122 GUID format validation. | Automated conftest verification (`conftest verify`) — 24/24 tests passed | **PASS (G07.6 Implemented)** |
| **AC-G07-24** | Azure Storage Backend Policy Hardening | Harden Azure storage backend policy ([`policies/azure/storage_backend.rego`](file:///home/tharuka/projects/infraflow/policies/azure/storage_backend.rego)) enforcing strict data-plane authentication (`use_azuread_auth = true`) and rejecting `use_oidc = true` alone to eliminate shared key fallback. | Automated conftest verification (`conftest verify`) — 19/19 tests passed | **PASS (G07.6 Implemented)** |
| **AC-G07-25** | Reusable Azure Workflow Security Hardening | Harden `.github/workflows/reusable-tf-azure.yml` with unconditional repository boundary check (`WORKFLOW_REPO`), 40-character hexadecimal `WORKFLOW_SHA` validation, strict `HIGH,CRITICAL` severity enforcement, and `plan-metrics.json` cleanup trap. | `actionlint`, `zizmor` (0 findings), and adversarial vectors 37–39, 45 | **PASS (G07.6 Implemented)** |
| **AC-G07-26** | Dedicated 45-Vector Adversarial Integration Suite | Author comprehensive 45-vector adversarial suite ([`tests/test_azure_adversarial_integration.py`](file:///home/tharuka/projects/infraflow/tests/test_azure_adversarial_integration.py)) covering identity substitution, audience wildcards, storage tampering, scanner bypasses, and fail-closed summary aggregation. | `python3 -m unittest tests/test_azure_adversarial_integration.py` (45/45 passed) | **PASS (G07.6 Implemented)** |
| **AC-G07-27** | Offline Local Regression Harness Expansion (303 Checks) | Expand Section 18 of `scripts/validate-local.sh` to 26 dedicated Azure checks (increasing total platform checks from 302 to 303). Verify 100% offline ($0.00 cloud spend) with zero regressions across G01–G07.5. | `scripts/validate-local.sh` execution (303/303 PASS) | **PASS (G07.6 Implemented)** |
| **AC-G07-28** | Adversarial Evidence & Hardening Documentation | Produce comprehensive security audit and adversarial report ([`docs/evidence/G07/G07-AZURE-SECURITY-HARDENING-REPORT.md`](file:///home/tharuka/projects/infraflow/docs/evidence/G07/G07-AZURE-SECURITY-HARDENING-REPORT.md)) detailing threat model analysis, vulnerability remediation, and test matrices. | Documentation audit and link verification | **PASS (G07.6 Implemented)** |
| **AC-G07-29** | Zero Cloud Spend & Regression Invariant | Guarantee exactly $0.00 cloud spend and zero live credentials. Maintain 100% pass rate across 299 Python tests and 171 OPA Rego unit tests. | Automated test suite execution | **PASS (G07.6 Implemented)** |

---

## 20. Milestone G07.7 — Acceptance Criteria (External Azure Consumer Integration & Multi-Cloud Release Readiness)

Milestone G07.7 integrates and validates the completed Azure Cloud-Free Adapter against an independent external consumer repository (`TM-threemavithana/infraflow-consumer-test`) on actual GitHub Actions runners ($0.00 cloud spend, zero credentials, no PR merges, no release tags).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G07-30** | External Consumer Integration & Immutable Pinning | Integrate `.github/workflows/reusable-tf-azure.yml` into consumer workflow (`infraflow-azure-plan.yml`) pinned to immutable 40-character commit SHA (`de8ff47dc513ea88892ef29b363e419d396b4290`). Ensure zero live credentials and no `id-token: write` permission. | GitHub Actions CI Execution ([Run 44864588624](https://github.com/TM-threemavithana/infraflow-consumer-test/actions/runs/44864588624)) | **PASS (G07.7 Implemented)** |
| **AC-G07-31** | Pure Offline Speculative Planning Fixture | Implement consumer smoke test fixture (`test/g07-azure-adapter-smoke/`) using native `terraform_data` resource, avoiding any provider authentication requirement while generating valid speculative plan metrics (`total-changes: 1`, `has-changes: true`). | `terraform init -backend=false` & `terraform plan` execution on GHA | **PASS (G07.7 Implemented)** |
| **AC-G07-32** | 7-Output Contract Verification on GHA | Assert all 7 contract outputs in consumer CI (`verify-cloud-free-outputs`): `authorization-status: not-applicable` (never `authorized`), `plan-status: success`, `azure-auth-status: disabled`, `security-status: success`, `has-changes: true`, `has-destructive-changes: false`, `total-changes: 1`. | Automated assertion step in `infraflow-azure-plan.yml` | **PASS (G07.7 Implemented)** |
| **AC-G07-33** | 36-Vector External Negative Security Test Harness | Author and execute independent negative security harness ([`scripts/run_azure_negative_tests.py`](file:///home/tharuka/projects/infraflow/scripts/run_azure_negative_tests.py)) on GitHub Actions runners, asserting 100% rejection across 36 bypass, path traversal, naming, and OPA policy attack scenarios. | GHA runner execution — 36/36 vectors passed | **PASS (G07.7 Implemented)** |
| **AC-G07-34** | SEC-02 Fail-Closed PR Event Security Assertion | Validate that untrusted pull requests requesting live Azure credentials (`enable-azure-auth: true` on `pull_request` event) fail closed immediately before any toolchain execution. | GHA step assertion (`verify-pr-event-security`) | **PASS (G07.7 Implemented)** |
| **AC-G07-35** | Historical Milestone Regression Parity (G04–G07 GCP) | Confirm zero regression across existing consumer workflows: G04 speculative plan, G05 AWS adapter, G06 protected apply simulation, and G07 GCP adapter all pass with 100% success on PR event. | GitHub Actions PR #5 checks (37/37 checks PASS) | **PASS (G07.7 Implemented)** |
| **AC-G07-36** | Multi-Cloud External Integration Evidence Report | Produce comprehensive integration evidence report ([`docs/evidence/G07/G07-AZURE-EXTERNAL-INTEGRATION-REPORT.md`](file:///home/tharuka/projects/infraflow/docs/evidence/G07/G07-AZURE-EXTERNAL-INTEGRATION-REPORT.md)) documenting workflow runs, contract outputs, adversarial matrices, multi-cloud comparison, and release readiness. | Documentation audit and link verification | **PASS (G07.7 Implemented)** |

---

## 21. Milestone G08.1 — Acceptance Criteria (Multi-Repository Adoption Foundation & Consumer Onboarding Toolkit)

Milestone G08.1 establishes an enterprise-grade onboarding model, consumer configuration contract, self-service repository template, automated validation tooling, and three isolated reference consumer fixtures (Networking, Application, Data Platform) with zero live cloud infrastructure provisioning ($0.00 spend).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G08-01** | Multi-Repository Adoption Architecture | Define comprehensive adoption architecture ([`docs/architecture/G08-MULTI-REPOSITORY-ADOPTION.md`](file:///home/tharuka/projects/infraflow/docs/architecture/G08-MULTI-REPOSITORY-ADOPTION.md)), 5-stage lifecycle model, platform vs consumer responsibility matrix, and centralized policy distribution model. | Documentation audit | **PASS (G08.1 Implemented)** |
| **AC-G08-02** | Consumer Onboarding Guide & Versioning Policy | Author developer-friendly onboarding guide ([`docs/adoption/CONSUMER-ONBOARDING-GUIDE.md`](file:///home/tharuka/projects/infraflow/docs/adoption/CONSUMER-ONBOARDING-GUIDE.md)) and platform versioning policy ([`docs/adoption/PLATFORM-VERSIONING-AND-UPGRADES.md`](file:///home/tharuka/projects/infraflow/docs/adoption/PLATFORM-VERSIONING-AND-UPGRADES.md)) detailing immutable 40-character commit SHA pinning. | Documentation audit | **PASS (G08.1 Implemented)** |
| **AC-G08-03** | Self-Service Consumer Repository Template | Implement `templates/consumer-repository/` containing standard caller workflow (`.github/workflows/infraflow.yml`), versioned contract (`infraflow.config.yaml`), cloud-free reference module (`terraform_data`), native unit tests, and template README. | Filesystem inspection & `actionlint` | **PASS (G08.1 Implemented)** |
| **AC-G08-04** | Standardized Consumer Configuration Contract | Define strict versioned schema for `infraflow.config.yaml` specifying `consumer_id`, `workload_type`, `terraform_dir`, `platform_ref`, `platform_sha`, `adapter`, and mandatory security controls. Reject mutable refs, path traversal, unknown keys, and cloud auth requests. | `validate-consumer.py` schema validation | **PASS (G08.1 Implemented)** |
| **AC-G08-05** | Automated Consumer Validation Tooling | Implement Python validation utility ([`scripts/validate-consumer.py`](file:///home/tharuka/projects/infraflow/scripts/validate-consumer.py)) checking config schema, workspace containment, symlink security, workflow permissions (`contents: read`), and commit SHA pinning. | CLI execution & test suite | **PASS (G08.1 Implemented)** |
| **AC-G08-06** | Multi-Consumer Reference Fixtures (3 Archetypes) | Implement three independent reference fixtures: Networking ([`fixtures/consumers/networking/`](file:///home/tharuka/projects/infraflow/fixtures/consumers/networking/)), Application ([`fixtures/consumers/application/`](file:///home/tharuka/projects/infraflow/fixtures/consumers/application/)), and Data Platform ([`fixtures/consumers/data-platform/`](file:///home/tharuka/projects/infraflow/fixtures/consumers/data-platform/)) with distinct contracts and native tests. | `terraform test` & `validate-consumer.py` | **PASS (G08.1 Implemented)** |
| **AC-G08-07** | Dedicated Consumer Onboarding Test Suite | Implement comprehensive 31-test unit and integration suite ([`tests/test_consumer_onboarding.py`](file:///home/tharuka/projects/infraflow/tests/test_consumer_onboarding.py)) covering valid configs, schema violations, path traversals, symlink escapes, excessive permissions, and CLI execution. | `python3 -m unittest tests/test_consumer_onboarding.py` (31/31 passed) | **PASS (G08.1 Implemented)** |
| **AC-G08-08** | Local Validation Harness Expansion (Section 19) | Expand `scripts/validate-local.sh` with Section 19 quality gates (18 new checks, raising total platform checks from 303 to 321). Verify 100% offline ($0.00 cloud spend) with zero regressions across G01–G07. | `scripts/validate-local.sh` execution | **PASS (G08.1 Implemented)** |

---

## 22. Milestone G08.2 — Acceptance Criteria (Independent Multi-Repository Adoption & External Fleet Integration)

Milestone G08.2 deploys, configures, and validates three independent external consumer repositories on live GitHub Actions runners across AWS, Azure, and GCP adapters ($0.00 cloud spend, zero live credentials, fail-closed policy enforcement).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G08-09** | Platform G08 Feature Branch Publication & CI Gate | Publish `feature/g08-consumer-onboarding` to `TM-threemavithana/infraflow` and open PR [#6](https://github.com/TM-threemavithana/infraflow/pull/6). Verify all mandatory CI checks pass cleanly. | GitHub Actions CI Execution ([PR #6](https://github.com/TM-threemavithana/infraflow/pull/6)) | **PASS (G08.2 Implemented)** |
| **AC-G08-10** | Three Independent External Consumer Repositories Created | Provision three dedicated public GitHub repositories under `TM-threemavithana`: [`infraflow-consumer-networking`](https://github.com/TM-threemavithana/infraflow-consumer-networking), [`infraflow-consumer-application`](https://github.com/TM-threemavithana/infraflow-consumer-application), and [`infraflow-consumer-data-platform`](https://github.com/TM-threemavithana/infraflow-consumer-data-platform). | GitHub API & Repository Verification | **PASS (G08.2 Implemented)** |
| **AC-G08-11** | Independent Consumer Onboarding & Local Contract Validation | Onboard each consumer with schema v1.0 contract (`infraflow.config.yaml`), caller workflow, and cloud-free `terraform_data` modules. Verify 15/15 checks pass per repo (45/45 total). | `scripts/validate-consumer.py` execution (45/45 passed) | **PASS (G08.2 Implemented)** |
| **AC-G08-12** | External Multi-Cloud GitHub Actions Execution Verification | Trigger and verify live pull request workflows across all three external repositories. All runs succeed cleanly calling AWS, Azure, and GCP reusable workflows. | GHA Runs [44870873397](https://github.com/TM-threemavithana/infraflow-consumer-networking/actions/runs/44870873397), [44870894843](https://github.com/TM-threemavithana/infraflow-consumer-application/actions/runs/44870894843), [44870921177](https://github.com/TM-threemavithana/infraflow-consumer-data-platform/actions/runs/44870921177) | **PASS (G08.2 Implemented)** |
| **AC-G08-13** | Output Contract Enforcement on Live Runners | Verify all seven reusable workflow outputs (`plan-status`, `<cloud>-auth-status`, `security-status`, `authorization-status`, `has-changes`, `has-destructive-changes`, `total-changes`) aggregated cleanly on live runners. | GHA Run Step Summaries & Job Logs | **PASS (G08.2 Implemented)** |
| **AC-G08-14** | Platform Centralization & Zero Redundant Policy Invariant | Verify 0 policies, 0 scanners, and 0 workflow logic duplicated in consumer repositories. Centralized governance ensures 100% policy inheritance. | Filesystem audit across consumer fleet | **PASS (G08.2 Implemented)** |
| **AC-G08-15** | Multi-Repository Adversarial & Security Testing | Execute 8-scenario adversarial test suite verifying fail-closed rejection of mutable references (`@main`), path traversals, disabled scanners, `write-all` permissions, and `pull_request_target` escalations. | Automated adversarial suite execution | **PASS (G08.2 Implemented)** |
| **AC-G08-16** | Historical Regression & Cloud Spend Invariant | Guarantee exactly $0.00 cloud infrastructure spend across all four repositories. Verify 100% pass across 321/321 platform quality checks and historical consumer integrity. | `scripts/validate-local.sh` (321/321 PASS) | **PASS (G08.2 Implemented)** |

---

## 23. Milestone G08.3 — Acceptance Criteria (Centralized Governance, Policy Enforcement & Consumer Trust Hardening)

Milestone G08.3 establishes centralized governance, Open Policy Agent (OPA) policy enforcement, supply chain trust hardening, and fleet auditing across all participating consumer repositories ($0.00 cloud spend, zero live credentials, fail-closed policy gates).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G08-17** | 4-Layer Defense-in-Depth Governance Model | Formulate and document the four-layer governance model (Layer A: Local Validator, Layer B: Reusable Governance Workflow, Layer C: GitHub Branch Rulesets, Layer D: Central Fleet Audit) in [`docs/security/G08-CONSUMER-GOVERNANCE-MODEL.md`](file:///home/tharuka/projects/infraflow/docs/security/G08-CONSUMER-GOVERNANCE-MODEL.md). | Documentation audit & architecture review | **PASS (G08.3 Implemented)** |
| **AC-G08-18** | Critical Onboarding Validation Tooling Hardening | Refactor [`scripts/validate-consumer.py`](file:///home/tharuka/projects/infraflow/scripts/validate-consumer.py) to resolve GOV-G08-01 (fail closed on missing workflow dir), GOV-G08-02 (enforce adapter invocation), and GOV-G08-03 (duplicate YAML key rejection, write permission rejection, `id-token: write` rejection, `pull_request_target` rejection, `secrets: inherit` rejection). | Python unit tests & adversarial suite | **PASS (G08.3 Implemented)** |
| **AC-G08-19** | Central OPA Consumer Governance Policy Contract | Implement [`policies/governance/consumer_governance.rego`](file:///home/tharuka/projects/infraflow/policies/governance/consumer_governance.rego) (package `governance.consumer`) with 14 enterprise deny rules and 23 dedicated unit tests ([`policies/governance/consumer_governance_test.rego`](file:///home/tharuka/projects/infraflow/policies/governance/consumer_governance_test.rego)). Elevate Rego test assertions from 171 to 194. | `conftest verify -p policies` (194/194 passed) | **PASS (G08.3 Implemented)** |
| **AC-G08-20** | Reusable Consumer Governance Gate Workflow | Implement [`.github/workflows/reusable-tf-governance.yml`](file:///home/tharuka/projects/infraflow/.github/workflows/reusable-tf-governance.yml) (`workflow_call`). Runs with `permissions: contents: read` (zero `id-token: write`), checks out platform at immutable SHA, executes authoritative validator, and evaluates Conftest OPA policies. | `actionlint` & `zizmor` (0 errors, 0 findings) | **PASS (G08.3 Implemented)** |
| **AC-G08-21** | Fleet-Wide Consumer Governance Rollout | Update external consumer repositories (`infraflow-consumer-networking`, `infraflow-consumer-application`, `infraflow-consumer-data-platform`) to invoke `reusable-tf-governance.yml` with `needs: [governance-gate]`. Verify all runs pass cleanly on GitHub Actions. | Live GitHub Actions execution across 3 repos | **PASS (G08.3 Implemented)** |
| **AC-G08-22** | Dedicated 40-Scenario Adversarial Test Suite | Implement comprehensive adversarial test suite ([`tests/test_consumer_governance.py`](file:///home/tharuka/projects/infraflow/tests/test_consumer_governance.py)) with 40 distinct test vectors proving fail-closed rejection of missing workflows, duplicate keys, privilege escalations, contradictory adapters, and tampered inputs. | `python3 -m unittest tests/test_consumer_governance.py` (40/40 passed) | **PASS (G08.3 Implemented)** |
| **AC-G08-23** | Central Fleet Governance Auditor Utility | Implement [`scripts/audit-consumer-fleet.py`](file:///home/tharuka/projects/infraflow/scripts/audit-consumer-fleet.py) providing Layer D out-of-band monitoring across all participating consumer repositories, auditing configuration, workflow invocation, and branch ruleset protection. | CLI execution across fixtures & external repos | **PASS (G08.3 Implemented)** |
| **AC-G08-24** | Local Validation Harness Expansion (Section 20) | Expand `scripts/validate-local.sh` with Section 20 quality gates (12 new checks, raising total platform checks from 321 to 333). Verify 100% offline ($0.00 cloud spend) with zero regressions across G01–G08.2. | `scripts/validate-local.sh` (333/333 passed) | **PASS (G08.3 Implemented)** |

---

## 24. Milestone G08.4 — Acceptance Criteria (Fleet-Wide Upgrade Orchestration, Configuration Drift Detection & Rollback Validation)

Milestone G08.4 establishes an automated, auditable, and fail-safe fleet-wide upgrade orchestration framework, versioned fleet registry, candidate compatibility verification, 15-vector drift detection, canary isolation, progressive rollout coordination, and atomic rollback guarantees across all consumer repositories ($0.00 cloud spend, zero live credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G08-25** | Fleet Upgrade Architecture & Operating Model | Define the six-stage upgrade lifecycle model (Inventory, Compatibility, Canary, Progressive, Verification, Rollback), strict cloud-free scope boundary, and 15-vector configuration/version/governance drift taxonomy in [`docs/architecture/G08-FLEET-UPGRADE-ARCHITECTURE.md`](file:///home/tharuka/projects/infraflow/docs/architecture/G08-FLEET-UPGRADE-ARCHITECTURE.md). | Documentation audit & architecture review | **PASS (G08.4 Implemented)** |
| **AC-G08-26** | Versioned Fleet Upgrade Manifest Specification | Implement authoritative registry [`config/fleet-manifest.yaml`](file:///home/tharuka/projects/infraflow/config/fleet-manifest.yaml) (Schema 1.0) defining registered consumers, adapters, workload types, current/target/rollback commit SHAs, candidate SHAs, and adapter workflow output contracts. | Schema validation & YAML parsing | **PASS (G08.4 Implemented)** |
| **AC-G08-27** | Automated Fleet Upgrade Orchestration & Planning Tool | Implement Python engine [`scripts/plan-fleet-upgrade.py`](file:///home/tharuka/projects/infraflow/scripts/plan-fleet-upgrade.py) with `--list`, `--inventory`, `--check-drift`, `--compatibility`, `--plan`, `--apply`, and `--rollback` actions. | CLI execution & test suite | **PASS (G08.4 Implemented)** |
| **AC-G08-28** | Platform Contract Compatibility Matrix Verification | Enforce pre-rollout evaluation verifying that candidate platform commit provides all mandatory outputs across AWS, Azure, GCP, and generic reusable workflows. Fail closed on contract deviations. | `plan-fleet-upgrade.py --compatibility` | **PASS (G08.4 Implemented)** |
| **AC-G08-29** | Controlled Canary Deployment & Fleet Isolation (AWS) | Upgrade canary consumer (`infraflow-consumer-networking`) to candidate platform commit (`1630e619...`). Verify that remaining consumers remain strictly isolated on baseline commit (`f1ad39fb...`). Verify canary CI passes 100% on GitHub Actions. | Live GitHub Actions execution ([Run 44876169983](https://github.com/TM-threemavithana/infraflow-consumer-networking/actions/runs/44876169983)) | **PASS (G08.4 Implemented)** |
| **AC-G08-29A**| Safe Rollback & Reversion Verification | Demonstrate atomic rollback restoring consumer configuration and workflow references back to known-good baseline (`f1ad39fb...`). Verify all local validation tests pass cleanly post-rollback. | CLI execution & test suite verification | **PASS (G08.4 Implemented)** |
| **AC-G08-30** | Progressive Rollout & Multi-Cloud Fleet CI Verification | Upon canary success, progressively upgrade Application (`infraflow-consumer-application`, Azure) and Data Platform (`infraflow-consumer-data-platform`, GCP) consumers. Verify all GitHub Actions CI runs pass cleanly. | Live GitHub Actions execution ([Run 44876281497](https://github.com/TM-threemavithana/infraflow-consumer-application/actions/runs/44876281497) & [Run 44876291264](https://github.com/TM-threemavithana/infraflow-consumer-data-platform/actions/runs/44876291264)) | **PASS (G08.4 Implemented)** |
| **AC-G08-31** | Dedicated 32-Scenario Adversarial Upgrade Test Suite | Implement comprehensive test suite [`tests/test_fleet_upgrades.py`](file:///home/tharuka/projects/infraflow/tests/test_fleet_upgrades.py) (32 tests) verifying manifest schema rules, staged planning, 15-vector drift detection, breaking change detection, canary failure containment, and rollback atomicity. | `python3 -m unittest tests/test_fleet_upgrades.py` (32/32 passed) | **PASS (G08.4 Implemented)** |
| **AC-G08-32** | Local Validation Harness Expansion (Section 21) | Expand `scripts/validate-local.sh` with Section 21 quality gates (14 new checks, raising total platform checks from 333 to 347). Verify 100% offline ($0.00 cloud spend) with zero regressions across G01–G08.3. | `scripts/validate-local.sh` (347/347 passed) | **PASS (G08.4 Implemented)** |

---

## 25. Milestone G08.5 — Acceptance Criteria (Final Multi-Repository Integration, Security Review & v0.6.0 Release)

Milestone G08.5 finalizes G08 by merging upstream platform PR #6, repinning all three consumer repositories to the platform merge commit, verifying pre-merge CI, merging consumer PRs into their respective `main` branches, proving post-merge CI on `main`, validating fleet-wide drift-free compliance, and publishing official release v0.6.0 ($0.00 cloud spend, zero live credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G08-33** | Upstream Platform PR #6 Merge & Post-Merge CI Verification | Squash-and-merge platform PR [#6](https://github.com/TM-threemavithana/infraflow/pull/6) into `main` (commit `be51718f06a2662099500a710e93e6e8201b4f1c`). Verify platform post-merge CI passes with 100% success on GitHub Actions. | GitHub Actions CI Execution ([Run 44879938738](https://github.com/TM-threemavithana/infraflow/actions/runs/44879938738)) | **PASS (G08.5 Implemented)** |
| **AC-G08-34** | Fleet Manifest Lifecycle Reconciliation & SHA Invariants | Reconcile [`config/fleet-manifest.yaml`](../../config/fleet-manifest.yaml) to distinguish historical release SHA (`2ce0ddd5...`), historical baseline SHA (`f1ad39fb...`), candidate SHA (`be51718f...`), and approved deployment target SHA (`be51718f...`). | Manifest validation & YAML parsing | **PASS (G08.5 Implemented)** |
| **AC-G08-35** | Transactional Upgrade Engine & Filesystem Atomicity | Enhance `apply_consumer_upgrade()` in `plan-fleet-upgrade.py` with strict pre-validation, in-memory staging, full file backup, atomic replacement (`tempfile` + `os.replace`), and automated compensating rollback. Add 4 dedicated regression tests (Tests 33–36). | `python3 -m unittest tests/test_fleet_upgrades.py` (36/36 passed) | **PASS (G08.5 Implemented)** |
| **AC-G08-36** | Pre-Merge Consumer Re-Verification Against Platform Merge Commit | Repin all three external consumer PRs to platform merge commit `be51718f06a2662099500a710e93e6e8201b4f1c`. Verify pre-merge CI passes on GitHub Actions: Networking (Run 44880081215), Application (Run 44880086808), Data Platform (Run 44880094359). | GitHub Actions CI Runs | **PASS (G08.5 Implemented)** |
| **AC-G08-37** | Consumer Fleet PR Merges & Post-Merge CI Verification on Main | Squash-and-merge all three consumer PRs into `main`: Networking (`f27c9eb`), Application (`0c2bca2`), Data Platform (`e9de14a`). Trigger and verify post-merge CI runs on `main` pass 100%: Networking (Run 44880340776), Application (Run 44880350636), Data Platform (Run 44880355737). | Live GitHub Actions execution on `main` across all 3 consumer repos | **PASS (G08.5 Implemented)** |
| **AC-G08-38** | Fleet-Wide Configuration & Version Drift Audit | Execute `scripts/plan-fleet-upgrade.py --check-drift --fleet-root ~/projects` across all consumer clones. Confirm zero configuration drift, zero workflow drift, and zero version drift across all repositories. | CLI execution — Verdict: CLEAN (NO DRIFT) | **PASS (G08.5 Implemented)** |
| **AC-G08-39** | Out-of-Band Central Fleet Governance Audit | Execute `scripts/audit-consumer-fleet.py --check-remote --fleet-root ~/projects`. Audit all three external repositories via GitHub API. Confirm 100% compliance across all registered workloads. | CLI execution — Fleet Status: COMPLIANT | **PASS (G08.5 Implemented)** |
| **AC-G08-40** | Final Multi-Repository Release Evidence Report & v0.6.0 Publishing | Produce comprehensive release evidence report ([`docs/evidence/G08/G08-FINAL-RELEASE-REPORT.md`](../evidence/G08/G08-FINAL-RELEASE-REPORT.md)), update root `README.md`, tag git release `v0.6.0`, and publish GitHub Release with full supply-chain attestations. | Documentation audit & GitHub release publication | **PASS (G08.5 Implemented)** |

---

## 26. Milestone G09.1 — Acceptance Criteria (Fleet Observability, Structured Telemetry & Central Compliance Dashboard Foundation)

Milestone G09.1 establishes the foundational observability and compliance architecture for the InfraFlow enterprise platform, introducing standardized OpenTelemetry/RFC 5424 structured event schemas, automated sensitive secret scrubbing, deterministic SHA-256 event integrity protection, an offline 5-pillar compliance scoring engine, multi-format dashboard exporters (JSON, GitHub Step Summary Markdown, offline standalone HTML), and a supply-chain hardened scheduled observability pipeline ($0.00 cloud spend, zero live credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G09-01** | G09 Operational Maturity Architecture Specification | Formulate and document the four-pillar operational maturity framework (Observability & Telemetry, Compliance Dashboard, Drift Detection, Automated Upgrades), event taxonomy, scoring engine mathematics, and STRIDE security model in [`docs/architecture/G09-OPERATIONAL-MATURITY-ARCHITECTURE.md`](file:///home/tharuka/projects/infraflow/docs/architecture/G09-OPERATIONAL-MATURITY-ARCHITECTURE.md). | Documentation audit & architecture review | **PASS (G09.1 Implemented)** |
| **AC-G09-02** | Structured Telemetry Emission Engine | Implement standardized telemetry CLI utility [`scripts/emit-telemetry.py`](file:///home/tharuka/projects/infraflow/scripts/emit-telemetry.py) generating schema v1.0 JSON-Lines events across 10 lifecycle events (`governance_gate_evaluated`, `security_scan_completed`, `speculative_plan_completed`, `contract_verified`, etc.) with ISO 8601 timestamps and execution context. | Schema validation & CLI execution | **PASS (G09.1 Implemented)** |
| **AC-G09-03** | Sensitive Data Redaction & Anti-Tampering Engine | Enforce multi-tier regex redaction (AWS access keys, GitHub tokens `ghp_`/`github_pat_`, JWTs, private keys, passwords) and compute deterministic SHA-256 integrity digests over canonicalized payload fields to detect out-of-band tampering. | Python unit tests & adversarial vectors | **PASS (G09.1 Implemented)** |
| **AC-G09-04** | Central Compliance Scoring Engine & Multi-Format Exporters | Implement [`scripts/generate-compliance-dashboard.py`](file:///home/tharuka/projects/infraflow/scripts/generate-compliance-dashboard.py) executing a deterministic 5-pillar scoring algorithm (20% weight per pillar: Contract Validity, Supply Chain Immutability, Mandatory Scanners, Least Privilege, Version Drift) exporting JSON, Markdown step summaries, and standalone offline-ready HTML dashboards. | CLI verification across fixtures & repos | **PASS (G09.1 Implemented)** |
| **AC-G09-05** | Central Fleet Observability Workflow Pipeline | Implement [`.github/workflows/fleet-observability.yml`](file:///home/tharuka/projects/infraflow/.github/workflows/fleet-observability.yml) running on weekly schedule (`0 6 * * 1`) and `workflow_dispatch` with strict least privilege (`contents: read`), zero live cloud credentials, generating compliance dashboards and publishing step summaries. | `actionlint` & `zizmor` (0 errors, 0 findings) | **PASS (G09.1 Implemented)** |
| **AC-G09-06** | Dedicated 31-Scenario Observability & Compliance Test Suite | Implement comprehensive test suite [`tests/test_observability_and_compliance.py`](file:///home/tharuka/projects/infraflow/tests/test_observability_and_compliance.py) (31 tests) verifying event schemas, secret scrubbing, anti-tampering verification, scoring algorithms, drift impacts, and threshold enforcement gates. | `python3 -m unittest tests/test_observability_and_compliance.py` (31/31 passed) | **PASS (G09.1 Implemented)** |
| **AC-G09-07** | Local Validation Harness Expansion (Section 22) | Expand `scripts/validate-local.sh` with Section 22 quality gates (15 new checks, raising total platform checks from 347 to 362). Verify 100% offline ($0.00 cloud spend) with zero regressions across G01–G08.5. | `scripts/validate-local.sh` (362/362 passed) | **PASS (G09.1 Implemented)** |
| **AC-G09-08** | Milestone Verification Evidence Report | Produce comprehensive milestone verification report [`docs/evidence/G09/G09-1-OBSERVABILITY-AND-COMPLIANCE-REPORT.md`](file:///home/tharuka/projects/infraflow/docs/evidence/G09/G09-1-OBSERVABILITY-AND-COMPLIANCE-REPORT.md) capturing all test results, architecture invariants, security posture, and zero-spend compliance. | Documentation review & audit | **PASS (G09.1 Implemented)** |

---

## 27. Milestone G09.2 — Acceptance Criteria (Continuous State & Speculative Drift Detection Simulation)

Milestone G09.2 establishes a provider-neutral, multi-cloud Continuous State & Speculative Drift Detection Simulation engine, supporting AWS, Azure, and GCP resources. It introduces deterministic 6-category drift classification (NO_DRIFT, ATTRIBUTE_DRIFT, UNTRACKED_RESOURCE, RESOURCE_DELETED, UNKNOWN_RESOURCE, STATE_INCONSISTENCY), severity calculation (CRITICAL to NONE), strict schema validation, symlink rejection, identity binding, sensitive secret scrubbing, telemetry bus integration (`drift_detected`, `drift_assessment_completed`, `drift_assessment_failed`), and backward-compatible integration with the Central Compliance Dashboard ($0.00 cloud spend, zero live credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G09-09** | Infrastructure Drift Detection Security Architecture | Document drift architecture, comparison models, three core drift categories, difference between simulation and live cloud drift detection, and STRIDE threat mitigations in [`docs/security/G09-DRIFT-DETECTION.md`](file:///home/tharuka/projects/infraflow/docs/security/G09-DRIFT-DETECTION.md). | Documentation audit & architecture review | **PASS (G09.2 Implemented)** |
| **AC-G09-10** | Normalized Multi-Cloud State Schema & Fixtures | Implement Schema v1.0 normalized resource representations and create comprehensive fixtures across AWS, Azure, GCP, and malformed vectors in [`fixtures/drift/`](file:///home/tharuka/projects/infraflow/fixtures/drift/). | Schema validation & fixture parsing | **PASS (G09.2 Implemented)** |
| **AC-G09-11** | Speculative Drift Simulation Engine | Implement [`scripts/simulate-drift.py`](file:///home/tharuka/projects/infraflow/scripts/simulate-drift.py) evaluating expected vs observed state snapshots, supporting attribute drift, untracked resources (shadow IT), and remote deletions across AWS, Azure, and GCP. | CLI execution & test suite | **PASS (G09.2 Implemented)** |
| **AC-G09-12** | Deterministic Classification & Severity Calculation | Enforce deterministic classification (`NO_DRIFT`, `ATTRIBUTE_DRIFT`, `UNTRACKED_RESOURCE`, `RESOURCE_DELETED`, `UNKNOWN_RESOURCE`, `STATE_INCONSISTENCY`) and severity weighting (`CRITICAL` for security downgrades/deletions, `HIGH`, `MEDIUM`, `NONE`). | Python unit tests & adversarial vectors | **PASS (G09.2 Implemented)** |
| **AC-G09-13** | Strict Security Boundaries & Secret Sanitization | Enforce strict JSON schema validation, explicit symlink rejection (`os.path.islink`), repository/workspace identity binding, and automated multi-tier sensitive secret scrubbing. Strictly no automatic remediation. | Adversarial unit tests & symlink vectors | **PASS (G09.2 Implemented)** |
| **AC-G09-14** | Telemetry Bus Event Integration | Integrate [`scripts/emit-telemetry.py`](file:///home/tharuka/projects/infraflow/scripts/emit-telemetry.py) to publish `drift_detected`, `drift_assessment_completed`, and `drift_assessment_failed` events with canonical SHA-256 integrity digests. | Telemetry schema validation & CLI tests | **PASS (G09.2 Implemented)** |
| **AC-G09-15** | Central Compliance Dashboard Drift Integration | Integrate per-consumer drift assessments into [`scripts/generate-compliance-dashboard.py`](file:///home/tharuka/projects/infraflow/scripts/generate-compliance-dashboard.py) under Pillar 5 (Drift Integrity), preserving backward compatibility while applying explicit evidence and penalties. | Dashboard generation & CLI execution | **PASS (G09.2 Implemented)** |
| **AC-G09-16** | Dedicated 34-Scenario Adversarial Test Suite & Harness Integration | Implement [`tests/test_drift_detection.py`](file:///home/tharuka/projects/infraflow/tests/test_drift_detection.py) (34 tests) and integrate Section 23 into `scripts/validate-local.sh` (15 new checks, 377 total platform checks). | `validate-local.sh` (377/377 passed) | **PASS (G09.2 Implemented)** |

---

## 28. Milestone G09.3 — Acceptance Criteria (Automated Upgrade Campaigns & Lifecycle Tracking)

Milestone G09.3 implements Pillar 4 of the InfraFlow Operational Maturity Architecture, establishing a production-grade Fleet Upgrade Campaign Orchestration & Lifecycle Tracking Engine ([`scripts/orchestrate-campaign.py`](file:///home/tharuka/projects/infraflow/scripts/orchestrate-campaign.py)). It introduces cryptographically signed Schema v1.0 upgrade campaigns, a 7-stage deterministic lifecycle state machine (PLANNED to COMPLETED/ROLLED_BACK), fail-closed Canary Gate enforcement, pre-flight and post-flight quality gates (contract compatibility, compliance scoring >=90%, and zero critical drift), transactional rollback orchestration, zero-cost simulated PR and branch generation, telemetry bus event emissions, and central compliance dashboard integration ($0.00 cloud spend, zero live credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G09-17** | Upgrade Campaign Security & Lifecycle Specification | Document multi-stage rollout architecture, 7-stage lifecycle state machine, Canary Gate model, and STRIDE threat mitigations in [`docs/operations/G09-UPGRADE-CAMPAIGNS.md`](file:///home/tharuka/projects/infraflow/docs/operations/G09-UPGRADE-CAMPAIGNS.md). | Documentation audit & architecture review | **PASS (G09.3 Implemented)** |
| **AC-G09-18** | Deterministic Campaign Initialization & Signatures | Implement `--create` generating Schema v1.0 JSON state files with deterministic SHA-256 signature calculated over canonical state. Anti-tampering rejection verified. | Unit tests & CLI execution | **PASS (G09.3 Implemented)** |
| **AC-G09-19** | Fail-Closed Canary Gate Enforcement | Enforce strict isolation blocking `--execute-stage progressive` whenever canary workloads are `PENDING`, `RUNNING`, or `FAILED` (`CanaryGateError`). | Adversarial unit tests & CLI validation | **PASS (G09.3 Implemented)** |
| **AC-G09-20** | Pre-Flight Compliance & State Drift Gates | Enforce caller workflow contract compatibility, mandatory compliance score threshold (>=90%), and halting of workloads exhibiting `CRITICAL` state drift. | Unit tests & drift fixtures | **PASS (G09.3 Implemented)** |
| **AC-G09-21** | Zero-Cost Simulated PR & Branch Dispatch | Generate deterministic simulated PR metadata (`infraflow/upgrade-<short>`), PR numbers, and review markdown summaries with zero live external API calls. | Schema check & PR body audit | **PASS (G09.3 Implemented)** |
| **AC-G09-22** | Transactional & Emergency Rollback Orchestration | Implement `--rollback` and `--auto-rollback` restoring registered `rollback_sha` references and updating campaign state to `ROLLED_BACK`. | Dry-run & transactional tests | **PASS (G09.3 Implemented)** |
| **AC-G09-23** | Telemetry & Compliance Dashboard Integration | Extend telemetry schema with campaign lifecycle events and integrate `--campaign-file` into central compliance dashboard reporting. | Telemetry validation & dashboard render | **PASS (G09.3 Implemented)** |
| **AC-G09-24** | Dedicated Adversarial Test Suite & Harness Integration | Author 32-test suite [`tests/test_upgrade_campaigns.py`](file:///home/tharuka/projects/infraflow/tests/test_upgrade_campaigns.py) and add Section 24 to `scripts/validate-local.sh` (15 new checks, raising platform quality checks to 392). | `validate-local.sh` (392/392 passed) | **PASS (G09.3 Implemented)** |

---

## 29. Milestone G09.4 — Acceptance Criteria (Enterprise Governance Automation & Final Operational Maturity Verification)

Milestone G09.4 finalizes Phase G09 by consolidating scheduled observability, multi-tenant fleet compliance scoring, continuous state drift simulation, and automated upgrade campaigns into a unified, fail-closed Enterprise Governance Verification Engine ([`scripts/verify-operational-maturity.py`](../../scripts/verify-operational-maturity.py)). It introduces deterministic SHA-256 evidence attestation signatures, fail-closed compliance threshold enforcement, critical drift circuit-breakers, Canary Gate validation, and a complete root [`README.md`](../../README.md) redesign ($0.00 cloud spend, zero live credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G09-25** | Operational Maturity Governance Architecture | Formulate and document the 4-pillar unified governance verification framework, CLI specifications, and threat boundaries in [`docs/operations/G09-OPERATIONAL-MATURITY-VERIFICATION.md`](../operations/G09-OPERATIONAL-MATURITY-VERIFICATION.md). | Documentation audit & review | **PASS (G09.4 Implemented)** |
| **AC-G09-26** | Unified Operational Verification Engine CLI | Implement [`scripts/verify-operational-maturity.py`](../../scripts/verify-operational-maturity.py) orchestrating Telemetry (P1), Compliance (P2), Drift (P3), and Campaigns (P4) with full options suite (`--manifest`, `--fleet-root`, `--drift-dir`, `--campaign-file`, `--telemetry-file`, `--enforce-threshold`, `--output-json`, `--output-markdown`, `--emit-telemetry`). | CLI execution & option test suite | **PASS (G09.4 Implemented)** |
| **AC-G09-27** | Deterministic Cryptographic Report Signatures | Compute deterministic SHA-256 report attestation signatures over canonical report payload representations (`report_signature`), strictly detecting and rejecting tampered evidence files. | Unit tests `test_signature_*` & CLI validation | **PASS (G09.4 Implemented)** |
| **AC-G09-28** | Fail-Closed Compliance Threshold Enforcement | Evaluate multi-tenant compliance across 5 governance pillars; enforce minimum fleet compliance threshold (`--enforce-threshold`, default 90.0%), failing closed with exit code 1 if violated. | Adversarial tests & CLI threshold tests | **PASS (G09.4 Implemented)** |
| **AC-G09-29** | Multi-Cloud State Drift Integration & Circuit-Breaker | Ingest drift reports across AWS, Azure, GCP; detect critical severity drift as a blocking governance circuit-breaker, enforcing read-only safety with zero destructive automated remediation. | Adversarial fixtures & CLI execution | **PASS (G09.4 Implemented)** |
| **AC-G09-30** | Upgrade Campaign Lifecycle & Canary Verification | Ingest campaign state; verify Canary Gate enforcement (blocking progressive rollout when canary is pending/failed), SHA-256 state signatures, and rollback preparedness (`rollback_sha`). | Unit tests & tampered campaign tests | **PASS (G09.4 Implemented)** |
| **AC-G09-31** | Supply-Chain & Defensive Security Guards | Enforce strict symlink rejection (`os.path.islink`), path traversal protection (`..`), and automatic recursive secret scrubbing across all exported payloads. | Adversarial security unit tests | **PASS (G09.4 Implemented)** |
| **AC-G09-32** | 32-Scenario Adversarial Test Suite & Harness Section 25 | Author [`tests/test_operational_maturity.py`](../../tests/test_operational_maturity.py) (32 tests) and add Section 25 to `scripts/validate-local.sh` (15 checks, raising platform quality checks to 407). | `validate-local.sh` (407/407 passed) | **PASS (G09.4 Implemented)** |

---

## 30. Milestone G10.1 — Acceptance Criteria (Unified Platform Developer Experience, CLI & Diagnostic Engine)

Milestone G10.1 establishes the unified developer experience (DevEx) for the InfraFlow enterprise platform, introducing the single-binary-like command-line utility ([`scripts/infraflow-cli.py`](../../scripts/infraflow-cli.py)). It consolidates platform diagnostics (`infraflow doctor`), consumer onboarding validation (`infraflow validate`), continuous state and speculative drift detection simulation (`infraflow drift`), and fleet upgrade campaign lifecycle management (`infraflow upgrade`). Furthermore, it introduces intelligent OPA/Conftest policy error enrichment, fail-closed symlink guards, and automated secret redaction ($0.00 cloud spend, zero live credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G10-01** | Unified CLI Architecture Specification | Formulate and document the unified CLI architecture, 12-check diagnostic matrix, policy error enhancement pipeline, and STRIDE threat boundaries in [`docs/architecture/G10-CLI-ARCHITECTURE.md`](G10-CLI-ARCHITECTURE.md). | Documentation audit & review | **PASS (G10.1 Implemented)** |
| **AC-G10-02** | Unified Platform CLI Engine | Implement [`scripts/infraflow-cli.py`](../../scripts/infraflow-cli.py) with subcommands (`doctor`, `validate`, `drift`, `upgrade`) and standardized flags (`--json`, `--verbose`, `--no-color`). Strictly reject `shell=True` in all subprocesses. | CLI execution & test suite | **PASS (G10.1 Implemented)** |
| **AC-G10-03** | Non-Destructive Platform Doctor (12 Dimensions) | Implement `infraflow doctor` evaluating 12 dimensions: Python (>=3.10), Terraform (>=1.6.0), Git, TFLint, Trivy, Conftest, Actionlint, Zizmor, Directory Hierarchy, Rego Policies, Dependencies, Git Workspace. | CLI execution (Text & JSON) | **PASS (G10.1 Implemented)** |
| **AC-G10-04** | Intelligent Policy Error Enrichment | Implement `PolicyErrorEnhancer` mapping raw Conftest deny outputs to human-readable Policy IDs, severity classifications, resource names, exact source line numbers, and actionable remediation advice. | Adversarial policy evaluation tests | **PASS (G10.1 Implemented)** |
| **AC-G10-05** | Continuous Drift Simulation Integration | Implement `infraflow drift` wrapping continuous state and speculative drift detection simulation with `--enforce-zero-drift` CI gating, Markdown/JSON export, and telemetry emission. | Adversarial drift fixtures & CLI gates | **PASS (G10.1 Implemented)** |
| **AC-G10-06** | Fleet Upgrade Planning & Rollout Integration | Implement `infraflow upgrade` wrapping fleet manifest evaluation, staged dry-run planning, Canary Gate enforcement, and local upgrade/rollback execution. | CLI execution & dry-run plan audit | **PASS (G10.1 Implemented)** |
| **AC-G10-07** | Defensive Security Guards & Secret Redaction | Enforce fail-closed symbolic link rejection (`os.path.islink`), path traversal protection (`..`), and automatic recursive secret scrubbing across all console streams and exported payloads. | Adversarial security unit tests | **PASS (G10.1 Implemented)** |
| **AC-G10-08** | 19-Scenario CLI Test Suite & Harness Section 26 | Author [`tests/test_cli.py`](../../tests/test_cli.py) (19 tests) and add Section 26 to `scripts/validate-local.sh` (13 checks, raising platform quality checks to 420). | `validate-local.sh` (420/420 passed) | **PASS (G10.1 Implemented)** |

---

## 31. Milestone G10.2 — Acceptance Criteria (Self-Service Consumer Onboarding & Scaffolding)

Milestone G10.2 introduces automated, self-service consumer repository onboarding and scaffolding via `infraflow init` (`infraflow/scaffold.py`) and registration engine (`infraflow/registrar.py`). It enables application teams to rapidly bootstrap production-grade infrastructure repositories with pre-configured cloud adapters (AWS, Azure, GCP), standard GitHub Actions CI/CD workflows, valid `infraflow.config.yaml` contracts, and automated fleet manifest registration ($0.00 cloud spend, zero live credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G10-09** | Consumer Scaffolding Engine | Implement `ConsumerScaffolder` generating Terraform project structures, GitHub Actions workflow caller configs, and contract schemas for AWS, Azure, and GCP. | Unit tests & directory output audit | **PASS (Completed)** |
| **AC-G10-10** | Central Fleet Registration | Implement `ConsumerRegistrar` validating existing contracts, preventing duplicate IDs, and deterministically inserting consumer entries into `fleet.manifest.yaml`. | Adversarial registration tests | **PASS (Completed)** |
| **AC-G10-11** | Interactive & Non-Interactive CLI | Implement `infraflow init` supporting interactive prompts and full CLI flags (`--name`, `--repo`, `--adapter`, `--env`, `--workload`, `--register`). | CLI execution tests | **PASS (Completed)** |
| **AC-G10-12** | Fail-Closed Security Guards | Enforce strict path traversal checks (`..`), directory containment checks, and duplicate consumer ID rejections. | Adversarial path traversal tests | **PASS (Completed)** |
| **AC-G10-13** | Dedicated Scaffolding Test Suite & Section 26.2 | Author `tests/test_scaffolding.py` (20 tests) and expand `scripts/validate-local.sh` (20 checks, raising total quality checks to 427). | `validate-local.sh` (427/427 passed) | **PASS (Completed)** |

---

## 32. Milestone G10.3 — Acceptance Criteria (Consumer Secret Defense & Semantic Destruction Protection)

Milestone G10.3 implements deep security defense mechanisms protecting enterprise consumers from credential leaks and catastrophic semantic destruction of persistent infrastructure resources. It introduces a mandatory consumer-side secret scanning engine (`infraflow/scanner.py`, `scripts/scan-secrets.py`), centralized reusable workflow integration, and a centralized semantic OPA policy (`policies/common/critical_resources.rego`) evaluating deletion, replacement orderings, malformed plans, and generic confirmation tokens ($0.00 cloud spend, zero live credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G10-14** | Consumer Secret Scanning Engine | Implement `SecretScanner` scanning consumer repositories before plan generation for AWS keys, GitHub tokens, PEM private keys, passwords, GCP keys, Slack tokens, and Bearer tokens. | `tests/test_secret_scanner.py` (18 tests) | **PASS (Completed)** |
| **AC-G10-15** | Zero Raw Secret Exposure Invariant | Enforce multi-tier masking and redaction (`SecretSanitizer`) ensuring zero raw credentials leak in logs, step summaries, or JSON outputs. | Redaction assertions & report checks | **PASS (Completed)** |
| **AC-G10-16** | Binary & Placeholder Filtering | Explicitly exclude binary plan artifacts (`tfplan`, `*.tfplan.binary`) and filter legitimate Terraform variable interpolations (`${var.*}`) from false-positive detection. | Fixture scans & test assertions | **PASS (Completed)** |
| **AC-G10-17** | Mandatory Central Governance Gate | Embed secret scanner in `.github/workflows/reusable-tf-governance.yml`; reject consumer attempts to disable scanners via `enforce_mandatory_scanners: false`. | `validate-consumer.py` & actionlint/zizmor | **PASS (Completed)** |
| **AC-G10-18** | Multi-Cloud Critical Resource Protection | Implement `policies/common/critical_resources.rego` protecting databases, KMS keys, storage accounts, IAM roles, and network security perimeters across AWS, Azure, and GCP. | `conftest verify` (64/64 passed) | **PASS (Completed)** |
| **AC-G10-19** | Semantic Action Differentiation | Evaluate direct deletions (`["delete"]`), destroy-before-create (`["delete", "create"]`), and create-before-destroy (`["create", "delete"]`) replacements; reject malformed actions. | `tests/test_critical_resources.py` (19 tests) | **PASS (Completed)** |
| **AC-G10-20** | Generic Token Rejection & Cryptographic Gate | Strictly reject generic approval tokens (`confirm`, `true`, `force`, `approved`); enforce cryptographic confirmation token binding (`infraflow-destruction-confirmation-v1`). | Conftest unit tests & adversarial plans | **PASS (Completed)** |
| **AC-G10-21** | External Consumer Adversarial Matrix | Update `infraflow-consumer-test` with synthetic secret fixtures, critical destruction fixtures, and automated verification script (5/5 checks passing). | Consumer test script execution | **PASS (Completed)** |
| **AC-G10-22** | Dedicated Test Suites & Local Harness Section 27 | Author `test_secret_scanner.py` (18 tests), `test_critical_resources.py` (19 tests), and Section 27 in `scripts/validate-local.sh` (15 checks, raising quality checks to 442). | `validate-local.sh` (442/442 passed) | **PASS (Completed)** |

---

## 33. Milestone G10.3.1 — Acceptance Criteria (Security Integration Assurance & Decommission Hardening)

Milestone G10.3.1 performs independent security integration verification and hardening across the entire InfraFlow delivery surface. It ensures that mandatory consumer secret scanning is consistently integrated and executed across all core delivery workflows (`reusable-tf-plan.yml`, `reusable-tf-aws.yml`, `reusable-tf-azure.yml`, `reusable-tf-gcp.yml`, `reusable-tf-security.yml`, `reusable-tf-governance.yml`), eliminates substring heuristic authorization bypasses in `policies/common/critical_resources.rego`, enforces Conftest `--all-namespaces` evaluation across Azure and GCP workflows, hardens workflow input guards against scanner disabling, and introduces an end-to-end 16-scenario security integration test suite ($0.00 cloud spend, zero live credentials).

| Criterion ID | Objective | Description | Verification Method | Pass / Fail Status |
|---|---|---|---|---|
| **AC-G10-23** | Multi-Workflow Secret Scanning Integration | Embed mandatory secret scanning (`scripts/scan-secrets.py`) across all 6 core workflows (`plan`, `aws`, `azure`, `gcp`, `security`, `governance`) with output propagation (`secret-scan-status`). | Workflow inspection, actionlint, zizmor | **PASS (Completed)** |
| **AC-G10-24** | Multi-Cloud All-Namespaces Conftest Evaluation | Ensure `conftest test` includes `--all-namespaces` across Azure and GCP workflows so `package common.critical_resources` is actively evaluated against Terraform plan JSON. | Workflow inspection & conftest tests | **PASS (Completed)** |
| **AC-G10-25** | Decommission Substring Bypass Remediation | Remove substring heuristic (`contains(lower(rc.address), "decommission")`) in `critical_resources.rego`; enforce platform-controlled, cryptographically signed plan confirmation (`is_plan_authorized`). | Rego unit tests (66/66) & fixtures | **PASS (Completed)** |
| **AC-G10-26** | Workflow Guard Input Enforcement | Add defensive input verification rejecting `enable-policy-evaluation: false`, `enable-trivy: false`, and `enable-conftest: false` across `reusable-tf-plan.yml` and `reusable-tf-security.yml`. | Bash guard assertions & unit tests | **PASS (Completed)** |
| **AC-G10-27** | Dedicated Integration Test Suite (16 Tests) | Implement `tests/test_g10_security_integration.py` covering positive/negative critical deletions, decommission authorization, replacement ordering, malformed plans, zero-leakage, and workflow guards. | `unittest` (16/16 passed) | **PASS (Completed)** |
| **AC-G10-28** | Local Validation Harness Expansion (Section 28) | Expand `scripts/validate-local.sh` with Section 28 (13 automated checks), raising platform quality gates to 455/455 passing checks. | `validate-local.sh` (455/455 passed) | **PASS (Completed)** |

---

## 34. Quality Gate Definitions

To achieve status **PASS** for G01 through G10:
1. Every milestone architecture and implementation document must exist, be fully elaborated, and be internally consistent.
2. All reusable workflows and caller examples must pass `actionlint` and `zizmor` without errors or warnings.
3. All reference Terraform modules must pass format check, validation, and native mock-provider test assertions.
4. All negative test fixtures and input guards must fail as expected with appropriate error codes.
5. The local validation runner script (`scripts/validate-local.sh`) must complete with exit code 0 (455/455 checks passing).
6. Git status must remain clean of untracked temporary files and state caches.
7. Any capability not executable locally (e.g. live cloud credential exchange) must remain simulation-only and fail-closed.
8. External consumer integration must be validated on actual GitHub Actions runners across both `push` and `pull_request` events with zero live cloud spend ($0.00).
