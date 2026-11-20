# InfraFlow Automated Verified Policy Gate Model

## 1. Purpose & Solo-Engineer Governance Model

The **InfraFlow Verified Policy Gate Model** defines the automated, policy-driven governance framework regulating how speculative infrastructure plans advance toward deployment authorization.

In an enterprise organization with multiple engineers, deployment gates often incorporate manual peer reviews. However, in a **personal, solo-engineer portfolio project**, manual reviewer gates introduce structural challenges:
1. **Self-Review Deadlocks**: GitHub Environment protection rules prohibit pull request authors from approving their own changes when "Prevent self-review" is enforced.
2. **False Claims of Peer Review**: Documenting "human approval" when no other maintainers exist is misleading and undermines professional DevSecOps integrity.

To establish genuine, auditable DevSecOps governance, InfraFlow refactors the human approval gate into an **Automated Verified Policy Gate** (`verified-policy-gate`). The platform evaluates cryptographically verified provenance, static security analysis, compliance policies, and change blast radiuses entirely through automated, fail-closed machine logic.

---

## 2. Architecture & Separation of Duties

```
                    ┌────────────────────────┐
                    │      Developer /       │
                    │      Author PR         │
                    └───────────┬────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │ [Job: plan]            │
                    │  - Speculative Plan    │
                    │  - Trivy IaC Scan      │
                    │  - OPA Policy Scanning │
                    │  - Change Analysis     │
                    │  - Generate Manifest   │
                    │    (plan-manifest.json)│
                    │  - Purge Ephemeral Plan│
                    └───────────┬────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │ [Job: attest]          │
                    │  - Sigstore OIDC Token │
                    │  - actions/attest      │
                    │  - Record in Rekor     │
                    └───────────┬────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │ [Job: verify-attestation]
                    │  - Official 'gh' CLI   │
                    │  - Verify Digest & OIDC│
                    │  - Verify Repo & SHA   │
                    │  - Verify Policy Status│
                    └───────────┬────────────┘
                                │
                                ▼
    ================ VERIFIED POLICY GATE ================
    │                                                    │
    │  [Job: verified-policy-gate]                       │
    │  - Needs: [plan, attest, verify-attestation]       │
    │  - Evaluates:                                      │
    │    1. Speculative plan generation outcome          │
    │    2. Plan change classification & unknowns        │
    │    3. Trivy IaC misconfiguration scan outcome      │
    │    4. Conftest / OPA policy enforcement outcome    │
    │    5. Sigstore cryptographic attestation status    │
    │    6. Official 'gh attestation verify' status      │
    │    7. Destructive change policy enforcement        │
    │  - Fails Closed: exits 1 if ANY condition fails    │
    │  - Emits: authorization-status (authorized/rejected│
    │  - Renders: Detailed audit trail step summary      │
    │                                                    │
    ======================================================
                                │
                                ▼
                    ┌────────────────────────┐
                    │ Authorized / Rejected  │
                    │ Output State           │
                    └────────────────────────┘
```

> [!NOTE]
> **Production vs. Offline Provenance Architectures**:
> - **Authoritative Production Mechanism**: GitHub Artifact Attestations using GitHub Actions OIDC and Sigstore (`actions/attest`) verified via official `gh attestation verify`. Eliminates static long-lived private keys and enforces Rekor transparency log verification.
> - **Offline & Legacy Compatibility**: Asymmetric ECDSA NIST P-256 in-toto DSSE envelope signing remains available solely for offline unit testing, local attack simulations, and legacy backward compatibility. It is strictly excluded from authorizing live production policy gates.

---

## 3. Critical Architectural Distinctions

> [!IMPORTANT]
> **Three Explicit Architectural Boundaries**:
> 1. **Automated Cryptographic & Policy Verification (FULLY IMPLEMENTED & VERIFIED)**:
>    - Cryptographic verification proves machine-level data integrity, provenance authenticity, authoring workflow identity, source commit binding, and policy compliance.
>    - **Local Verification Reality**: The local test harness (`scripts/validate-local.sh`) executes completely offline using synthetic bundles, deterministic SHA-256 digests, and local static analyzers without requiring network access or cloud credentials.
>    - **Live CI Execution Reality**: The authoritative production workflow executes in live GitHub Actions, generating genuine Sigstore OIDC attestations recorded in the public Rekor transparency log and verified via `gh attestation verify`.
>    - **Dual Scanner Enforcement**: Both Trivy IaC scanning and Conftest OPA evaluation must succeed. Any skipped scanner or failure results in immediate rejection by the verified policy gate.
>    - **Platform Baseline Invariance**: Minimum security severity threshold is strictly pinned to `HIGH,CRITICAL` and mandatory platform OPA policies are immutable; consumer policies can only be evaluated additionally.
> 2. **Human Review Gate (NOT CONFIGURED / INACTIVE)**:
>    - Because this is a solo-engineer project, no human environment reviewer gate is active. The workflow does not pause for manual sign-off.
>    - The system never claims human approval occurred.
> 3. **Production Deployment Execution (DEFERRED TO G06)**:
>    - Milestone G04 focuses strictly on speculative planning, security analysis, attestation, and policy authorization.
>    - No cloud resources are provisioned ($0 budget preserved). `terraform apply` and `terraform destroy` are out of scope and deferred to Milestone G06.

---

## 4. Eight-Scenario Verified Policy Gate Decision Matrix

The automated verified policy gate evaluates all inputs and upstream states using a deterministic, fail-closed matrix:

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

## 5. Deployment Environment Context

The workflow parameter `environment` (default: `"production"`) supplies contextual metadata indicating the target deployment tier.
- It is recorded in the job summary and audit trail to contextualize change classifications and blast radiuses.
- It does **not** attach GitHub Environment protection rules or pause execution for manual sign-off, ensuring seamless continuous integration for the solo engineer.

---

## 6. Remote Branch Protection vs. Local Workflow Guards

> [!WARNING]
> **Operational Reality**:
> - **Local Workflow Branch-Guard Tests**: Verify that workflow guard logic rejects illegal paths, invalid SemVer, and commit mismatches. Verified 100% locally by `validate-local.sh`.
> - **Remote GitHub Branch Protection**: Rules enforced on GitHub (`Require pull request reviews before merging`, `Require status checks to pass`, `Do not allow bypassing`).
> - Local offline test scripts **cannot** execute or verify live remote GitHub branch protection. Remote branch protection is accurately documented as **UNVERIFIED (Requires live GitHub repository branch protection setup)**.

---

## 7. Signing Identity Separation in the Verified Policy Gate

The policy gate strictly separates **Preview Signers** from **Production Signers**:
- **Preview Signing Tier**: Used for speculative pull request plan generation. Emits `signing_tier: preview`.
- **Production Signing Tier**: Used for protected branch apply authorization. Emits `signing_tier: production` and requires signing by an authorized key in `PLATFORM_PRODUCTION_SIGNERS` (`3c27ef...`).
- When advancing toward production deployment, the gate enforces `--require-production-signer`. An ephemeral or preview key (even if well-formed and validly signed) is rejected with exit code 1.

---

## 8. Caller Workflow Security & Centrally Controlled Required Workflows

To prevent an attacker pull request from subverting the caller workflow:
1. **Centrally Controlled Required Workflows (GitHub Organization Rulesets)**:
   - Organization administrators enforce required workflows (e.g. `reusable-tf-security.yml`, `reusable-tf-plan.yml`) at the organization level.
   - Individual repository pull requests cannot delete or modify organization-required workflows.
2. **Mandatory Status Check Policy (Repository Branch Protection)**:
   - Repository settings enforce required status checks: `security` and `verified-policy-gate`.
   - If a PR deletes the security job from its caller workflow, the required status check is missing, and GitHub strictly blocks the merge.
3. **Least-Privilege PR Execution**:
   - Pull requests from untrusted branches or forks run strictly with `permissions: contents: read`.
   - Production secrets and cloud credentials are NEVER exposed to pull requests.

---

## 9. Production Attestation Architecture (GitHub Artifact Attestations / Sigstore OIDC)

In milestone **G04.1.4**, InfraFlow adopted **GitHub Artifact Attestations** (`actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2`) backed by GitHub OIDC and Sigstore as the authoritative production provenance model:

1. **Short-Lived Ephemeral Identity**:
   - Eliminates long-lived production private keys stored in GitHub Secrets.
   - The runner authenticates via GitHub's OpenID Connect provider (`id-token: write`, `attestations: write`).
   - Sigstore Fulcio issues a short-lived X.509 certificate bound to the repository, workflow, commit SHA, and runner identity.
   - The attestation is recorded in the Sigstore Rekor transparency log.
2. **Sanitized Plan Manifest Attestation**:
   - Rather than publishing raw plans or raw JSON, the platform creates `plan-manifest.json` binding the SHA-256 digest of both the binary `tfplan` and `tfplan.json`, repository, commit, run ID, actor, workflow, and security decision (`security_decision: passed`).
   - `actions/attest` cryptographically attests the sanitized manifest file.
3. **Strict Pre-Gate Attestation Verification**:
   - The pre-gate verification job (`verify-attestation`) verifies the Sigstore attestation and plan manifest using official `gh attestation verify` in GitHub Actions (with fallback to `scripts/verify-plan-integrity.py verify-attestation` for offline unit testing).
   - Machine verification strictly verifies: (1) manifest subject digest, (2) expected source repository, (3) expected source commit SHA, (4) expected signer workflow, (5) GitHub Actions OIDC issuer (`https://token.actions.githubusercontent.com`), and (6) manifest security decision (`security_decision: passed`).
   - Verified policy gate execution condition strictly mandates:
     `needs: [plan, attest, verify-attestation]` with programmatic validation of all job results.
   - Missing, skipped, unauthenticated, tampered, or cross-repository attestations fail closed immediately.
4. **Attestation Scope vs. Exact-Plan Application (Future G06 Requirement)**:
   - GitHub Artifact Attestation attests `plan-manifest.json`, which contains the cryptographic digests of the binary and JSON plans (`plan_file_sha256` and `plan_json_sha256`).
   - The original binary plan (`tfplan`) is purged immediately upon completion and is **not** retained as a build artifact, strictly preventing confidential infrastructure state exposure in public repositories.
   - Because the binary plan is not stored or transferred to downstream jobs, the platform **does not claim or enable exact-plan application** in current delivery. The attestation proves the authenticity of planning metadata and policy verification at planning time.
   - In future deployment milestones (**Milestone G06 — Protected Apply & Destroy**), exact-plan application will require private, KMS envelope-encrypted object storage (e.g. OIDC-authenticated S3/GCS) to persist binary plans securely and verify digests prior to apply.

---

## 10. Repository-Level Governance Ruleset & Enterprise Scaling Architecture

### 10.1 Current Architecture: Solo-Maintainer Rulesets
For the personal, public InfraFlow repositories (`TM-threemavithana/infraflow` and `TM-threemavithana/infraflow-consumer-test`), governance is enforced via repository-level GitHub Rulesets ([.github/rulesets/main-ruleset.json](file:///home/tharuka/projects/infraflow/.github/rulesets/main-ruleset.json)):
- **Pull Request Requirement (Solo-Maintainer Compatible)**: Changes must be submitted via PR (direct push blocked). Configured with `required_approving_review_count: 0` to prevent deadlocks for a solo maintainer, where GitHub prohibits authors from approving their own PRs.
- **Stale Approval Dismissal**: `dismiss_stale_reviews_on_push: true` automatically revokes approvals when new commits are introduced.
- **Strict Status Checks**: Branches must be up-to-date with `main` before merging (`strict_required_status_checks_policy: true`).
- **Enforced Check Source**: Status checks must originate from GitHub Actions (`integration_id: 15368`).
- **CODEOWNERS Ownership & Review Routing**: [.github/CODEOWNERS](file:///home/tharuka/projects/infraflow/.github/CODEOWNERS) assigns ownership of sensitive paths (`.github/workflows/**`, `policies/trust/**`, `scripts/verify-plan-integrity.py`).
- **Linear History & Force Push Blocks**: Non-fast-forward updates (`non_fast_forward`) and branch deletions (`deletion`) are blocked.
- **Zero Bypass Actors**: `bypass_actors: []` ensures platform rules apply equally to all contributors.

### 10.2 Job Permission Isolation
The reusable planning workflow strictly isolates elevated token permissions into independent jobs:
- **`plan` Job**: Granted `contents: read` only. Executes Terraform planning, Trivy scanner, and Conftest OPA policies. Generates sanitized `plan-manifest.json` and purges raw plans.
- **`attest` Job**: Granted `contents: read`, `id-token: write`, `attestations: write`. Downloads only the sanitized manifest, pre-validates metadata and policy passing status, and calls `actions/attest`. Never executes untrusted Terraform code.
- **`verify-attestation` Job**: Granted `contents: read` only. Executes official `gh attestation verify`.
- **`verified-policy-gate` Job**: Granted `contents: read` only. Programmatically evaluates upstream statuses and enforces fail-closed authorization.

### 10.3 Future Architecture: Enterprise Team Scaling Path
When adopted within enterprise teams with multiple engineers:
- The `verified-policy-gate` job can be supplemented with GitHub Environment Protection rules (`environment: production`) with `required_reviewers` and `prevent_self_review: true`.
- Centrally controlled organization-level rulesets enforce required workflows across all consumer repositories without repository-level configuration duplication.
- `required_approving_review_count` is elevated to 1+ with `require_code_owner_review: true` once multiple platform approvers are onboarded.
