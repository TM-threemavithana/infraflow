# InfraFlow Protected Environment Approval Model

## 1. Purpose & Separation of Duties

The **InfraFlow Approval Model** defines the operational and security criteria governing how speculative infrastructure plans advance toward deployment. It establishes strict separation of duties between change authors and approvers, combines human review with automated cryptographic provenance verification, and prevents stale, altered, or unauthorized plans from proceeding.

---

## 2. Separation of Duties & IAM Trust Model

```
                    ┌────────────────────────┐
                    │      Developer /       │
                    │      Author PR         │
                    └───────────┬────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │ Speculative Plan Job   │
                    │  - Generates Plan      │
                    │  - Evaluates Policies  │
                    │  - Signs Provenance    │
                    │    (Asymmetric ECDSA)  │
                    └───────────┬────────────┘
                                │
                                ▼
    =================== APPROVAL GATE ===================
    │                                                   │
    │  [1] Automated Cryptographic Provenance Gate:     │
    │      - Verify ECDSA digital signature against     │
    │        pinned trusted root                        │
    │      - Verify SHA-256 plan digests                │
    │      - Verify source commit SHA matches HEAD      │
    │      - Verify repository and workflow identity    │
    │      - Enforce policy evaluation was "passed"     │
    │                                                   │
    │  [2] Human Gate (GitHub Environment):             │
    │      - Environment: 'production-approval'         │
    │      - Required Reviewers (e.g., Platform Team)   │
    │      - Prevent self-review (author != reviewer)   │
    │      - Review sanitized Step Summary diff         │
    │                                                   │
    =====================================================
                                │
                                ▼
                    ┌────────────────────────┐
                    │ Gate Completion /      │
                    │ Downstream Delivery    │
                    └────────────────────────┘
```

---

## 3. Critical Architectural Distinction: Cryptographic Gate vs. Human Review

> [!IMPORTANT]
> **Cryptographic Verification Does NOT Prove Human Reviewer Approval**:
> - **Cryptographic Verification**: Proves machine-level data integrity, provenance authenticity, authoring workflow identity, source commit binding, and policy compliance. Rejection of an untrusted cryptographic key proves only that the artifact was signed by an unauthorized key—it does NOT prove or simulate human reviewer sign-off.
> - **Human Reviewer Gate**: Enforced exclusively by GitHub's proprietary Environment protection rules (`environment: production-approval`).
> - In an offline local verification harness ($0 budget, WSL2 runner), live human reviewer approval cannot be executed without a live GitHub Enterprise/Team SaaS account with configured environment reviewers.
> - Consequently, live human reviewer interactions are documented as **UNVERIFIED (Requires live GitHub Environment setup)**, while cryptographic plan-to-approval bindings are **PASS (Locally Verified)**.

---

## 4. Eight-Scenario Human Approval Verification Matrix

| Scenario ID | Test Scenario | Mechanism | Verification Method | Status |
|---|---|---|---|---|
| **SC-01** | **Authorized Reviewer Approval** | Designated engineer approves via GitHub UI | GitHub Environment Protection Rules | **UNVERIFIED (Cloud/SaaS setup required)** |
| **SC-02** | **Unauthorized Reviewer Rejection** | Non-listed user attempts to approve in UI | GitHub IAM Environment Gate | **UNVERIFIED (Cloud/SaaS setup required)** |
| **SC-03** | **Self-Review Prevention** | PR author attempts to approve their own PR | "Prevent self-review" GitHub setting | **UNVERIFIED (Cloud/SaaS setup required)** |
| **SC-04** | **Rejected Approval** | Reviewer clicks "Reject" in GitHub UI | Workflow job halts with `rejected`/`cancelled` | **UNVERIFIED (Cloud/SaaS setup required)** |
| **SC-05** | **Missing Reviewer Configuration** | Environment created without required reviewers | Workflow runs without pausing for review | **UNVERIFIED (Cloud/SaaS setup required)** |
| **SC-06** | **Approval Bypass Attempt (Direct Push)** | Malicious actor pushes directly to main branch | Branch protection + Cryptographic gate | **PASS (Locally Verified)** |
| **SC-07** | **Source Commit Mismatch After Plan** | Attacker introduces code after plan generated | Cryptographic commit binding (`$GITHUB_SHA`) | **PASS (Locally Verified - Test 10.28 / 11.12)** |
| **SC-08** | **Plan Digest Mismatch After Plan** | Attacker alters plan JSON or binary after approval | Cryptographic SHA-256 digest binding | **PASS (Locally Verified - Test 10.29, 10.30 / 11.9, 11.10)** |

---

## 5. Required GitHub Repository Environment Configuration

To activate the live human approval gate in GitHub Actions, consumer repositories must configure the target GitHub Environment:

1. **Navigate to Repository Settings**:
   `Settings` -> `Environments` -> `New environment`
2. **Environment Name**:
   Enter `production-approval` (matching `inputs.environment`).
3. **Environment Protection Rules**:
   - **Required reviewers**: Check this option and add designated platform security leads or deployment teams (e.g., `@my-org/platform-approvers`).
   - **Prevent self-review**: Check this box. This strictly prohibits pull request authors from approving their own infrastructure modifications.
   - **Deployment branches**: Restrict deployments to protected branches (e.g. `main` only).
   - **Wait timer** (Optional): Add an automated soaking window (e.g. 5 minutes).

---

## 6. Remote Branch Protection vs. Local Workflow Guards

> [!WARNING]
> **Operational Reality**:
> - **Local Workflow Branch-Guard Tests**: Verify that workflow guard logic rejects illegal paths, invalid SemVer, and commit mismatches. Verified 100% locally by `validate-local.sh`.
> - **Remote GitHub Branch Protection**: Rules enforced on GitHub (`Require pull request reviews before merging`, `Require status checks to pass`, `Do not allow bypassing`).
> - Local offline test scripts **cannot** execute or verify live remote GitHub branch protection. Remote branch protection is accurately documented as **UNVERIFIED (Requires live GitHub repository branch protection setup)**.

---

## 8. Signing Identity Separation in the Approval Gate

The approval gate strictly separates **Preview Signers** from **Production Signers**:
- **Preview Signing Tier**: Used for speculative pull request plan generation. Emits `signing_tier: preview`.
- **Production Signing Tier**: Used for protected branch apply authorization. Emits `signing_tier: production` and requires signing by an authorized key in `PLATFORM_PRODUCTION_SIGNERS` (`3c27ef...`).
- When advancing toward production deployment, the gate enforces `--require-production-signer`. An ephemeral or preview key (even if well-formed and validly signed) is rejected with exit code 1.

---

## 9. Caller Workflow Security & Centrally Controlled Required Workflows

To prevent an attacker pull request from subverting the caller workflow:
1. **Centrally Controlled Required Workflows (GitHub Organization Rulesets)**:
   - Organization administrators enforce required workflows (e.g. `reusable-tf-security.yml`, `reusable-tf-plan.yml`) at the organization level.
   - Individual repository pull requests cannot delete or modify organization-required workflows.
2. **Mandatory Status Check Policy (Repository Branch Protection)**:
   - Repository settings enforce required status checks: `security` and `approval-gate`.
   - If a PR deletes the security job from its caller workflow, the required status check is missing, and GitHub strictly blocks the merge.
3. **Least-Privilege PR Execution**:
   - Pull requests from untrusted branches or forks run strictly with `permissions: contents: read`.
   - Production secrets and cloud credentials are NEVER exposed to pull requests.

---

## 10. Production Attestation Architecture (GitHub Artifact Attestations / Sigstore OIDC)

In milestone **G04.1.4**, InfraFlow adopted **GitHub Artifact Attestations** (`actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2`) backed by GitHub OIDC and Sigstore as the authoritative production provenance model:

1. **Short-Lived Ephemeral Identity**:
   - Eliminates long-lived production private keys stored in GitHub Secrets.
   - The runner authenticates via GitHub's OpenID Connect provider (`id-token: write`, `attestations: write`).
   - Sigstore Fulcio issues a short-lived X.509 certificate bound to the repository, workflow, commit SHA, and runner identity.
   - The attestation is recorded in the Sigstore Rekor transparency log.
2. **Sanitized Plan Manifest Attestation**:
   - Rather than publishing raw plans or raw JSON, the platform creates `plan-manifest.json` binding the SHA-256 digest of both the binary `tfplan` and `tfplan.json`, repository, commit, run ID, actor, workflow, and security decision (`security_decision: passed`).
   - `actions/attest` cryptographically attests the sanitized manifest file.
3. **Strict Gate Verification**:
   - The approval gate verifies the Sigstore bundle and plan manifest using official `gh attestation verify` in GitHub Actions (with fallback to `scripts/verify-plan-integrity.py verify-attestation` for offline unit testing).
   - Approval gate execution condition strictly mandates:
     `needs.plan.result == 'success' && needs.plan.outputs.security-status == 'success' && needs.attest.result == 'success'`.
   - Missing, skipped, unauthenticated, tampered, or cross-repository attestations fail closed immediately before entering human review. Caller inputs cannot disable or bypass mandatory production verification.
   - Asymmetric ECDSA preview signing is maintained strictly for offline unit tests and legacy compatibility, and is never accepted as an alternative production authorization identity (`--require-production-signer` enforced).
4. **Attestation Scope vs. Exact-Plan Application (Future G06 Requirement)**:
   - GitHub Artifact Attestation attests `plan-manifest.json`, which contains the cryptographic digests of the binary and JSON plans (`plan_file_sha256` and `plan_json_sha256`).
   - The original binary plan (`tfplan`) is purged immediately upon completion and is **not** retained as a build artifact, strictly preventing confidential infrastructure state exposure in public repositories.
   - Because the binary plan is not stored or transferred to downstream jobs, the platform **does not claim or enable exact-plan application** in current delivery. The attestation proves the authenticity of planning metadata and policy verification at planning time.
   - In future deployment milestones (**Milestone G06 — Protected Apply & Destroy**), exact-plan application will require private, KMS envelope-encrypted object storage (e.g. OIDC-authenticated S3/GCS) to persist binary plans securely and verify digests prior to apply.

---

## 11. Repository-Level Governance Ruleset & Enterprise Scaling Architecture

### 11.1 Current Architecture: Repository-Level Rulesets
For the personal, public InfraFlow repositories (`TM-threemavithana/infraflow` and `TM-threemavithana/infraflow-consumer-test`), governance is enforced via repository-level GitHub Rulesets ([.github/rulesets/main-ruleset.json](file:///home/tharuka/projects/infraflow/.github/rulesets/main-ruleset.json)):
- **Pull Request Requirement (Solo-Maintainer Compatible)**: Changes must be submitted via PR (direct push blocked). Configured with `required_approving_review_count: 0` to prevent deadlocks for a solo maintainer, where GitHub prohibits authors from approving their own PRs.
- **Stale Approval Dismissal**: `dismiss_stale_reviews_on_push: true` automatically revokes approvals when new commits are introduced.
- **Strict Status Checks**: Branches must be up-to-date with `main` before merging (`strict_required_status_checks_policy: true`).
- **Enforced Check Source**: Status checks must originate from GitHub Actions (`integration_id: 15368`). Check context names must be verified against actual GitHub Actions check names during the first live PR run.
- **CODEOWNERS Ownership & Review Routing**: [.github/CODEOWNERS](file:///home/tharuka/projects/infraflow/.github/CODEOWNERS) assigns ownership of sensitive paths (`.github/workflows/**`, `policies/trust/**`, `scripts/verify-plan-integrity.py`). It provides ownership metadata and review routing; independent approval requires another trusted maintainer.
- **Linear History & Force Push Blocks**: Non-fast-forward updates (`non_fast_forward`) and branch deletions (`deletion`) are blocked.
- **Zero Bypass Actors**: `bypass_actors: []` ensures platform rules apply equally to all contributors.

### 11.2 Attestation Permission Isolation (Job Separation)
The reusable planning workflow strictly isolates elevated token permissions into an independent job:
- **`plan` Job**: Granted `contents: read` only. Executes Terraform planning, Trivy scanner, and Conftest OPA policies. Generates sanitized `plan-manifest.json` and purges raw plans.
- **`attest` Job**: Granted `contents: read`, `id-token: write`, `attestations: write`. Downloads only the sanitized manifest, pre-validates metadata and policy passing status, and calls `actions/attest`. Never executes untrusted Terraform code.
- **`approval-gate` Job**: Granted `contents: read` only. Evaluates environment protection rules and verifies provenance.

### 11.3 Future Architecture: Enterprise Centrally Controlled Rulesets
When adopted within enterprise GitHub Organizations:
- Centrally controlled organization-level rulesets enforce required workflows across all consumer repositories without repository-level configuration duplication.
- `required_approving_review_count` is elevated to 1+ with `require_code_owner_review: true` once multiple platform approvers are onboarded.
- Requires GitHub Organization on Team or Enterprise cloud tier ($0 budget preserved; no paid plans purchased).

> [!WARNING]
> **Operational Distinctions**:
> - **Local Ruleset Validation**: **PASS** (132/132 checks verify JSON schema, required checks, permission isolation, and security constraints).
> - **Live GitHub Settings**: **UNVERIFIED** (Requires live repository administrative activation).
> - **Live Human Reviewer Sign-Off**: **UNVERIFIED** (Simulated locally; requires live GitHub SaaS reviewer approval).
