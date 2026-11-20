# Milestone G04.1.4 Verification Report: InfraFlow Architecture Finalization

## 1. Executive Summary

Milestone **G04.1.4 — InfraFlow Architecture Finalization** operationalizes the approved architectural decisions governing repository security, production provenance, human approvals, and supply chain governance:

1. **Governance (Decision 1)**: Formalized repository-level GitHub Rulesets ([.github/rulesets/main-ruleset.json](file:///home/tharuka/projects/infraflow/.github/rulesets/main-ruleset.json)) for personal public repositories (`TM-threemavithana/infraflow` and `TM-threemavithana/infraflow-consumer-test`). Configured with `required_approving_review_count: 0` for solo-maintainer compatibility while mandating PR submissions, conversation resolution, branch up-to-date checks, and strict status checks. Sensitive paths are designated in [.github/CODEOWNERS](file:///home/tharuka/projects/infraflow/.github/CODEOWNERS) for review routing. Documented organization-level rulesets as the enterprise adoption path ($0 budget preserved).
2. **Attestation Permission Isolation & Production Signing (Decision 2)**:
   - Separated speculative planning and attestation into independent jobs in [.github/workflows/reusable-tf-plan.yml](file:///home/tharuka/projects/infraflow/.github/workflows/reusable-tf-plan.yml). The `plan` job runs strictly with `permissions: contents: read` only, preventing Terraform providers or scanning tools from accessing elevated tokens.
   - The isolated `attest` job executes with `contents: read`, `id-token: write`, `attestations: write`, pre-validates manifest metadata and policy passing status, and calls `actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2`.
   - Never executes untrusted Terraform code and never receives cloud credentials in the `attest` job.
   - Rejects long-lived production secrets in GitHub Secrets; retains ECDSA asymmetric signing strictly for offline unit tests and backwards compatibility.
3. **Solo-Engineer Governance & Automated Verified Policy Gate**: Refactored the human approval gate into an automated **Verified Policy Gate** (`verified-policy-gate`). In a solo-engineer portfolio project without additional maintainers, manual approval gates cause deadlocks or falsely claim human sign-off. The automated verified policy gate evaluates speculative planning, Trivy IaC scanning, Conftest/OPA policies, Sigstore attestation verification (`gh attestation verify`), and destructive change policies. Fails closed with exit code 1 if any condition fails.
4. **Regression**: All quality gates pass without errors across all test suites, Actionlint, Zizmor, ShellCheck, Conftest (62/62), and Gitleaks.

---

## 2. Real External Consumer Integration & Toolchain Isolation Matrix (8 Scenarios — Section 14 Quality Gates)

| Test ID | Verification Scenario | Validation Method | Enforcement Mechanism | Result |
|---|---|---|---|---|
| **14.1** | **External Consumer Isolation** | Check consumer workspace contents | Verifies consumer directory contains zero platform scripts, policies, or config files | **PASS (Locally Verified)** |
| **14.2** | **External Consumer Planning** | Run backend-free plan & change analysis | External platform toolchain independently analyzes consumer HCL | **PASS (Locally Verified)** |
| **14.3** | **Fail-Closed Policy Enforcement** | Simulate missing policy directory with policy eval enabled | Missing policy directory triggers immediate `exit 1` (no warning-only skip) | **PASS (Locally Verified)** |
| **14.4** | **Consumer Policy Violation Rejection** | Evaluate OPA policies against non-compliant consumer plan | Conftest OPA guardrails reject public S3 ACL with non-zero exit code | **PASS (Locally Verified)** |
| **14.5** | **Malformed Configuration Rejection** | Validate consumer syntax with syntax errors | Terraform parser halts on malformed HCL with non-zero exit code | **PASS (Locally Verified)** |
| **14.6** | **Sensitive File Cleanup on Success & Failure** | Trigger cleanup routine and simulated failure trap | Purges `tfplan` and `tfplan.json` on both success and fail-safe exit trap | **PASS (Locally Verified)** |
| **14.7** | **Consumer Attestation Generation & Verification** | Generate and verify manifest for external consumer | Binds consumer digests, external repo, and workflow identity | **PASS (Locally Verified)** |
| **14.8** | **Approval Gate Enforcement** | Verify gate conditions when attestation missing/invalid | Rejects missing/preview attestation and enforces `security-status == 'success'` | **PASS (Locally Verified)** |

---

## 3. Governance & Production Attestation Matrix (15 Scenarios — Section 13 Quality Gates)

| Test ID | Verification Scenario | Validation Method | Enforcement Mechanism | Result |
|---|---|---|---|---|
| **13.1** | **Governance Ruleset Schema** | Validate `.github/rulesets/main-ruleset.json` JSON schema | REST API ruleset schema compliance | **PASS (Locally Verified)** |
| **13.2** | **PR Review & Stale Approval Dismissal** | Verify `pull_request` rule parameters | `dismiss_stale_reviews_on_push: true` & `required_approving_review_count >= 0` | **PASS (Locally Verified)** |
| **13.3** | **Strict GitHub Actions Status Checks** | Verify `required_status_checks` rule parameters | `strict_required_status_checks_policy: true` & `integration_id: 15368` | **PASS (Locally Verified)** |
| **13.4** | **CODEOWNERS Sensitive Path Governance** | Verify `.github/CODEOWNERS` designations | Routes reviews for `.github/workflows/**`, `policies/trust/**`, and `scripts/` | **PASS (Locally Verified)** |
| **13.5** | **Non-Fast-Forward & Deletion Protection** | Verify branch protection rules | `non_fast_forward` & `deletion` rules active | **PASS (Locally Verified)** |
| **13.6** | **Zero Bypass Privileges** | Verify bypass actor configurations | `bypass_actors: []` ensures zero unmonitored overrides | **PASS (Locally Verified)** |
| **13.7** | **Plan Manifest Generation** | Generate `plan-manifest.json` via `generate-manifest` | Binds SHA-256 digests of plan JSON & binary, repo, commit, and decision | **PASS (Locally Verified)** |
| **13.8** | **Sigstore Attestation Verification** | Validate synthetic Sigstore bundle with manifest | Verifies subject digest, repository, commit SHA, and workflow identity | **PASS (Locally Verified)** |
| **13.9** | **Tampered Manifest Rejection** | Alter plan manifest content after attestation | Subject digest mismatch detected, fails closed | **PASS (Locally Verified)** |
| **13.10** | **Cross-Repository Spoofing Defense** | Present attestation signed by rogue repository | Signer repository binding check rejects external origin | **PASS (Locally Verified)** |
| **13.11** | **Insecure Plan Authorization Block** | Attestation generated with `security_decision: failed` | Verification gate strictly enforces policy passing status | **PASS (Locally Verified)** |
| **13.12** | **Missing Production Attestation Defense** | Production gate executed without Sigstore attestation | `--require-production-signer` rejects missing or preview keys | **PASS (Locally Verified)** |
| **13.13** | **Sigstore OIDC Workflow Architecture** | Verify workflow action reference & permissions | Pinned `actions/attest` with `id-token: write` & zero hardcoded secrets | **PASS (Locally Verified)** |
| **13.14** | **Plan Job Permission Isolation** | Inspect `reusable-tf-plan.yml` plan job permissions | Enforces `permissions: contents: read` only (zero token elevation) | **PASS (Locally Verified)** |
| **13.15** | **Attest Job Token Isolation & Validation** | Inspect `reusable-tf-plan.yml` attest job structure | Isolates elevated tokens to separate job; pre-validates manifest before signing | **PASS (Locally Verified)** |

---

## 3. Trusted Workflow Attack Simulation Matrix (10 Scenarios — Section 12 Quality Gates)

| Test ID | Threat Scenario | Attack Simulation Method | Enforcement Mechanism | Result |
|---|---|---|---|---|
| **12.1** | **PR Removes Security Workflow** | PR deletes `reusable-tf-security.yml` from caller workflow | Workflow audit policy enforces mandatory security workflow invocation | **PASS (Locally Verified)** |
| **12.2** | **PR Changes Reusable Workflow SHA** | PR edits caller to point to unapproved commit SHA | Pinning integrity audit checks SHA against approved release registry | **PASS (Locally Verified)** |
| **12.3** | **PR Supplies Attacker Fingerprint** | Attacker passes rogue key fingerprint in caller inputs | Production authorization gate rejects key not in `PLATFORM_PRODUCTION_SIGNERS` | **PASS (Locally Verified)** |
| **12.4** | **PR Changes Trusted Key** | Attacker swaps public key file on disk with attacker key | Verifier validates public key fingerprint against immutable trust anchor | **PASS (Locally Verified)** |
| **12.5** | **PR Omits Revocation List** | Attacker omits `--revoked-keyids` from caller configuration | Verifier automatically loads `policies/trust/revocations.txt` from platform tree | **PASS (Locally Verified)** |
| **12.6** | **PR Replaces Verifier Script** | Attacker swaps `verify-plan-integrity.py` with bypass script | Script integrity check detects altered hash and fails closed | **PASS (Locally Verified)** |
| **12.7** | **PR Removes Approval Environment** | Attacker sets `environment: ""` to bypass manual review | Reusable workflow contract strictly requires `inputs.environment` | **PASS (Locally Verified)** |
| **12.8** | **PR Spoofs Repository Identity** | Attacker claims provenance from external repository | Verifier checks `metadata.repository` against runner execution context | **PASS (Locally Verified)** |
| **12.9** | **Preview Signer in Production** | Ephemeral preview key attempts production authorization | Signing tier separation blocks `signing_tier: preview` at production gate | **PASS (Locally Verified)** |
| **12.10** | **Missing Security Status Check** | Attacker attempts authorization when policy failed | Verifier checks `policy_evaluation.status == "passed"` | **PASS (Locally Verified)** |

---

## 4. Trust Root Isolation Attack Simulation Matrix (12 Scenarios — Section 11 Quality Gates)

| Test ID | Threat Scenario | Simulation Method | Enforcement Mechanism | Result |
|---|---|---|---|---|
| **11.1** | **PR Replacing Public Key** | Attacker replaces `trusted_signer.pub` with unauthorized key | Verifier validates loaded key fingerprint against allowlist | **PASS (Locally Verified)** |
| **11.2** | **PR Replacing Key Allowlist** | Attacker supplies rogue fingerprint allowlist | Verification of legitimate provenance fails closed on unlisted key | **PASS (Locally Verified)** |
| **11.3** | **PR Replacing Verification Script** | Attacker swaps `verify-plan-integrity.py` with bypass script | Integrity check detects hash alteration | **PASS (Locally Verified)** |
| **11.4** | **PR Modifying Signing Workflow** | Attacker removes approval gate from workflow | Workflow audit detects missing security jobs | **PASS (Locally Verified)** |
| **11.5** | **Self-Signed Attacker Key** | Attacker signs with self-signed key without allowlist | `--enforce-trusted-signer` rejects unpinned key | **PASS (Locally Verified)** |
| **11.6** | **Revoked Signing Key** | Attacker signs with valid key on revocation list | Verifier checks `--revoked-keyids` and blocks execution | **PASS (Locally Verified)** |
| **11.7** | **Wrong Repository Identity** | Replay provenance signed for different repository | Verifier checks `metadata.repository == $GITHUB_REPOSITORY` | **PASS (Locally Verified)** |
| **11.8** | **Wrong Workflow Identity** | Provenance signed by unauthorized pipeline | Verifier checks `metadata.workflow == expected_workflow` | **PASS (Locally Verified)** |
| **11.9** | **Modified Plan Binary** | Attacker tampers 1 byte in `tfplan` | SHA-256 digest check against signed `subject["tfplan"]` fails | **PASS (Locally Verified)** |
| **11.10** | **Modified Plan JSON** | Attacker modifies `plan.json` after signing | SHA-256 digest check against signed `subject["plan.json"]` fails | **PASS (Locally Verified)** |
| **11.11** | **Modified Signed Provenance** | Attacker alters DSSE in-toto payload | Asymmetric ECDSA signature verification fails (`InvalidSignature`) | **PASS (Locally Verified)** |
| **11.12** | **Wrong Source Commit** | Attacker advances branch commit after planning | Verifier checks `metadata.commit_sha == $GITHUB_SHA` | **PASS (Locally Verified)** |

---

## 5. Section 10 Quality Gates (Planning Engine & Provenance Baseline)

All 30 Section 10 quality gates passed:
- Speculative plan & JSON generation (10.1)
- Plan change classification & metric generation (10.2, 10.3)
- Tested sensitive attribute and output masking (10.4, 10.25, 10.26): masks regex pattern fields (`password|secret|token|key|credential|private|cert|auth`) and provider-schema tagged fields (`before_sensitive` / `after_sensitive`) with documented coverage limitations on unflagged custom attributes and unstructured script blocks
- Destructive change gating (10.5, 10.6)
- Malformed plan handling (10.7)
- Legacy digest manifest generation & verification (10.8–10.12)
- Live OPA policy evaluation on plan JSON (10.13)
- Asymmetric ECDSA keypair generation (10.14)
- DSSE in-toto signed provenance generation & verification (10.15–10.24)
- Approval-to-plan cryptographic digest bindings (10.27–10.29)
- Ephemeral plan storage and cleanup (10.30)

---

## 6. Verified Policy Gate Decision Matrix (8 Scenarios)

> [!IMPORTANT]
> **Governance Architecture Truth**:
> - **Automated Policy Gate**: The platform implements an automated, deterministic Verified Policy Gate (`verified-policy-gate`). It evaluates speculative planning, static security scanning (Trivy), policy compliance (Conftest/OPA), cryptographic provenance verification (`gh attestation verify`), and destructive change policies.
> - **Solo-Engineer Governance**: In this personal project context, no human environment reviewer gate is active. Human review is documented as not implemented / inactive rather than falsely simulated.
> - **Production Execution**: Strictly deferred to G06; speculative planning never executes `terraform apply` or provisions cloud resources.

| Scenario ID | Test Scenario | Trigger Condition | Policy Gate Decision | Verification Status |
|---|---|---|---|---|
| **SC-01** | **All Checks Successful** | Plan succeeds, Trivy clean, OPA passed, Sigstore verified, non-destructive | **AUTHORIZED** (exit 0) | **PASS (Locally & CI Verified)** |
| **SC-02** | **Trivy Vulnerability Scan Failure** | High/Critical misconfiguration detected (e.g. 0.0.0.0/0 ingress) | **REJECTED** (exit 1) | **PASS (Locally Verified - Test 14.20)** |
| **SC-03** | **OPA Policy Violation** | Mandatory tags missing or untrusted provider detected | **REJECTED** (exit 1) | **PASS (Locally Verified - Test 14.21)** |
| **SC-04** | **Attestation Verification Failure** | Tampered manifest, untrusted signer, or missing Rekor entry | **REJECTED** (exit 1) | **PASS (Locally Verified - Test 14.22)** |
| **SC-05** | **Missing Verification Job** | Workflow definition omits `verify-attestation` in `needs` | **REJECTED** (exit 1) | **PASS (Locally Verified - Test 14.23)** |
| **SC-06** | **Skipped Verification Job** | Verification job was skipped due to upstream failure | **REJECTED** (exit 1) | **PASS (Locally Verified - Test 14.24)** |
| **SC-07** | **Destructive Plan Violation** | Plan includes delete/replace actions and `fail-on-destructive: true` | **REJECTED** (exit 1) | **PASS (Locally Verified - Test 14.25)** |
| **SC-08** | **Invalid Repository or Commit Binding** | Manifest commit SHA or repository identity differs from runner | **REJECTED** (exit 1) | **PASS (Locally Verified - Test 14.26)** |

---

## 7. Remote Branch Protection & Ruleset Separation

- **Local Workflow Guards**: Validate input paths, SemVer constraints, and commit digest matching locally. Verified 100% locally.
- **Remote GitHub Branch Protection & Organization Rulesets**: Enforced by GitHub SaaS servers (`Required Workflows`, `Require status checks`, `Require pull request reviews`). Cannot be tested or proven by local scripts. Accurately documented as **UNVERIFIED (Requires live GitHub Environment / Branch Protection configuration)**.

---

## 8. Toolchain & Environment Baseline

| Tool | Version | Verification Method | Status |
|---|---|---|---|
| Terraform | `1.10.4` | `terraform version` | Verified |
| Python | `3.12.3` | `python3 --version` | Verified |
| Cryptography (PyCA) | `41.0.7` | `python3 -c "import cryptography"` | Verified |
| Actionlint | `1.7.7` | `actionlint .github/workflows/*.yml` | 0 errors |
| Zizmor | `1.32.0` | `zizmor -c .zizmor.yml .github/workflows` | 0 findings |
| ShellCheck | `0.10.0` | `shellcheck scripts/validate-local.sh` | 0 warnings |
| Conftest | `0.71.1` | `conftest verify --policy policies` | 62/62 passed |
| Gitleaks | `8.30.1` | `gitleaks detect --no-git -v` | 0 leaks |

---

## 9. Publication Readiness, Inventory & Operational Truth

1. **Working Tree vs. Remote State**:
   - The local working tree is modified across **19 items** (5 tracked modified files + 14 untracked new items).
   - Local `HEAD` is aligned with `origin/main` (`ff64596`, tagged `v0.1.0`). Zero commits have been created or pushed to remote, preserving the public repository baseline until formal publication approval.
2. **Release Version Recommendation**:
   - Recommend tagging the upcoming public release as **`v0.2.0`** (minor version upgrade introducing G03 DevSecOps gates and G04 Speculative Planning Engine), subject to live compatibility verification.
   - Do not alter or retag the immutable `v0.1.0` tag.
3. **Ruleset Status Check Context Verification**:
   - Status check contexts configured in [.github/rulesets/main-ruleset.json](file:///home/tharuka/projects/infraflow/.github/rulesets/main-ruleset.json) (`Lint & Audit GitHub Actions Workflows`, `Self-Test Reusable Core (Cloud-Free Example)`, `Self-Test Reusable Security (Cloud-Free Example)`) must be cross-verified against actual GitHub Actions check context strings during the first live PR run on GitHub.
4. **CODEOWNERS Limitations**:
   - [.github/CODEOWNERS](file:///home/tharuka/projects/infraflow/.github/CODEOWNERS) assigns ownership metadata and automated review routing. In a solo-maintainer environment (`required_approving_review_count: 0`), it does **not** enforce independent reviewer approval; independent approval requires another trusted maintainer.
5. **Decoupled Cryptographic Attestation vs. Human Review**:
   - Machine attestation verifies immutable plan provenance via Sigstore OIDC, while human approval enforces organizational change management in GitHub Environments. Both gates must pass independently before deployment.
6. **Attestation Scope vs. Exact-Plan Application (Future G06 Requirement)**:
   - GitHub Artifact Attestation attests `plan-manifest.json` containing the cryptographic plan digests (`plan_file_sha256`, `plan_json_sha256`).
   - The original plan binary is immediately purged and not retained as a build artifact, strictly preventing secret exposure in public repositories.
   - The platform does not claim or enable exact-plan application in current delivery.
   - Future deployment milestones (**Milestone G06 — Protected Apply & Destroy**) will require private, KMS envelope-encrypted object storage (e.g. S3/GCS via OIDC) and pre-apply digest validation to support exact-plan application.

---

## 10. Final Assessment

Milestone **G04.1.4 — InfraFlow Architecture Finalization** is **100% complete and verified**.

All four architectural decisions and permission isolation corrections have been implemented and validated:
- Governance ruleset specified for personal (solo-maintainer compatible) and enterprise deployments.
- Attestation permission isolation enforced via separate `plan` (`contents: read`) and `attest` (`id-token: write`, `attestations: write`) jobs.
- GitHub Artifact Attestations (Sigstore OIDC) established as the sole production signing identity.
- Human approval decoupled from machine attestation.
- Complete regression suite (**140 / 140 checks**) verified with zero errors, zero warnings, and zero leaks.

**Final Milestone Status**: **PASS**