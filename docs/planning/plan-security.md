# InfraFlow Plan Security, Trust Isolation & Trusted Workflow Enforcement

## 1. Overview & Threat Context

Terraform execution plans capture sensitive operational data, including database passwords, API authentication tokens, internal network topologies, and private keys. 

InfraFlow implements strict **defense-in-depth** controls to prevent secret exposure, data leakage in public GitHub Actions artifacts, subversion of trust roots by untrusted pull requests, caller workflow tampering, and unauthorized promotion of speculative plans to production.

---

## 2. Cryptographic Provenance Architecture & Trust Root Isolation

> [!IMPORTANT]
> **Cryptographic Integrity vs. Cryptographic Authenticity**:
> - **Integrity Detection**: A SHA-256 digest alone proves whether an artifact was altered after the digest was calculated, but provides **zero authenticity** (it does not prove who generated the digest, nor does it prevent an attacker from substituting both the artifact and its digest).
> - **Cryptographic Authenticity**: An **authenticated digital signature** uses asymmetric public-key cryptography (NIST P-256 ECDSA / SHA-256) to bind execution metadata and cryptographic digests to an authenticable signer identity.
> - **Trust Root Requirement**: Packaging a public key alongside an untrusted signed payload without an independent trust root creates an **in-band key delivery vulnerability**—an adversary who can alter the artifact can replace both the signature and the public key. InfraFlow solves this by enforcing an **independent trust root** (pinned public keys, immutable platform trust anchors, and fingerprint allowlists).

### 2.1 The In-Toto DSSE Signed Provenance Model
InfraFlow implements the in-toto Statement v1 specification wrapped in a Dead Simple Signing Envelope (DSSE):
- **Payload Type**: `application/vnd.in-toto+json`
- **Signature Algorithm**: ECDSA with curve NIST P-256 (SECP256R1) and SHA-256
- **Signed Statement (`_type: https://in-toto.io/Statement/v1`)**:
  - `subject`: Binds the SHA-256 hashes of both `plan.json` and the binary `tfplan`.
  - `predicate`: Binds the builder workflow identity, repository (`$GITHUB_REPOSITORY`), source commit SHA (`$GITHUB_SHA`), workflow run ID, actor, Terraform version, signing tier, and policy evaluation outcome (`passed`).

### 2.2 Provenance DSSE Envelope Schema
```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64_encoded_canonical_in_toto_statement>",
  "signatures": [
    {
      "keyid": "<sha256_of_public_key_der>",
      "sig": "<base64_encoded_ecdsa_der_signature>",
      "publicKey": "-----BEGIN PUBLIC KEY-----\n..."
    }
  ]
}
```

### 2.3 Independent Trust Root & Anti-Substitution Protection
To defend against in-band key substitution attacks, the verifier (`scripts/verify-plan-integrity.py`) enforces an independent trust model:

1. **Authoritative Platform Trust Anchor**:
   - The platform defines a canonical trust root fingerprint:
     `3c27ef9e1e520fd8c6c04db2c19680e16cf3c95a72b5536a9cada058890f7e90`.
   - Any public key presented from disk or candidate artifacts must match this anchor or be registered in the authorized allowlist.
2. **Pinned Trusted Public Key (`--trusted-public-key`)**:
   - The verifier loads the public key from a trusted filesystem path outside the untrusted artifact (e.g. `policies/trust/trusted_signer.pub`).
   - The signature is verified directly against this pinned key.
   - If an allowlist is provided, the fingerprint of the loaded key file is checked against the allowlist to prevent local file substitution attacks.
3. **Fingerprint Allowlist (`--trusted-keyids`)**:
   - The verifier enforces that the signer's key ID belongs to an explicit list of authorized platform signing keys.
4. **Anti-Substitution Enforcement (`--enforce-trusted-signer`)**:
   - Enabled by default in workflow gates. If an untrusted public key is provided or embedded in an artifact, the gate rejects it immediately, preventing attackers from self-signing malicious plans.
5. **Key Revocation Blocklist (`--revoked-keyids` & Protected Registry)**:
   - Compromised or retired signing keys are placed on an explicit revocation blocklist (`policies/trust/revocations.txt`). Any provenance signed by a revoked key is rejected immediately, even if it is present in the allowlist.
6. **Comprehensive Binding Verification**:
   - Signer authenticity & unrevoked key status
   - Signing identity tier (`preview` vs `production`)
   - Repository identity (`environment.repository == $GITHUB_REPOSITORY`)
   - Workflow identity (`environment.workflow == expected_workflow`)
   - Commit SHA (`environment.commit_sha == $GITHUB_SHA`)
   - Policy evaluation status (`policyEvaluation.status == "passed"`)
   - Binary plan digest (`subject["tfplan"] == computed_digest`)
   - Plan JSON digest (`subject["tfplan.json"] == computed_digest`)

---

## 3. Caller Workflow Security & Trusted Configuration Architecture

A core insight of Milestone G04.1.3 is: **Pinning the reusable workflow does NOT protect the caller workflow**.

If an attacker submits a pull request, the PR branch contains its own version of `.github/workflows/ci.yml`. An attacker could attempt to subvert the platform by altering the calling workflow.

### 3.1 Caller Workflow Attack Vectors & Independent Defenses

| Caller Threat Vector | Attack Scenario | Platform Defense Mechanism | Enforcement Boundary |
|---|---|---|---|
| **Security Workflow Removal** | Attacker deletes `reusable-tf-security.yml` from `ci.yml` | **Organization Required Workflows / Branch Protection Status Checks**: If `security` status check is missing, merge is blocked (Test 12.1). | GitHub Ruleset / Branch Protection |
| **Workflow Reference Tampering** | Attacker points `uses:` to rogue commit or malicious fork | **Pinning Integrity Policy Audit**: Caller workflow must reference immutable platform SHAs matching the release tag (Test 12.2). | Repository CODEOWNERS / CI Guard |
| **Attacker Signer Fingerprint** | Attacker passes rogue `trusted-signer-keyids` in caller workflow | **Production Signer Authorization Gate**: Production approval strictly requires key enrollment in `PLATFORM_PRODUCTION_SIGNERS` (Test 12.3). | Workflow Execution Guard |
| **Trusted Key Substitution** | Attacker replaces `policies/trust/trusted_signer.pub` on disk | **Anti-Substitution Verification**: Pinned root anchor rejects unauthorized public key files (Test 12.4). | Cryptographic Verification |
| **Revocation List Omission** | Attacker omits `--revoked-keyids` from caller configuration | **Hardcoded Platform Revocation Registry**: Verifier automatically loads `policies/trust/revocations.txt` from protected platform tree (Test 12.5). | Toolchain Automation |
| **Verifier Script Replacement** | Attacker replaces `verify-plan-integrity.py` with `exit 0` script | **Toolchain Integrity Verification**: Script hash verified against canonical release hash (Test 12.6). | Execution Guard / Checkout Isolation |
| **Approval Environment Removal** | Attacker sets `environment: ""` to bypass manual review | **Workflow Policy Audit**: Reusable workflow strictly requires `inputs.environment` (Test 12.7). | Reusable Workflow Contract |
| **Repository Identity Spoofing** | Attacker claims provenance from rogue repository | **Immutable Context Binding**: Verifier checks `$GITHUB_REPOSITORY` against runner execution context (Test 12.8). | Cryptographic Binding |
| **Preview Key Production Bypass** | Attacker uses ephemeral PR key for production deployment | **Signing Tier Separation**: Production gate strictly requires `signing_tier: production` (Test 12.9). | Signing Trust Engine |
| **Missing Security Status Authorization** | Attacker attempts approval when security check failed | **Provenance Policy Enforcement**: Verification fails unless `policy_evaluation.status == "passed"` (Test 12.10). | Attestation Verification |

### 3.2 Trusted Configuration Principles
The following configurations **must NEVER be controlled by untrusted PR inputs**:
1. **Trusted Signer Fingerprints**: Resolved from protected platform trust anchors (`policies/trust/trusted_signer.pub` or environment-protected secrets).
2. **Revocation Registry**: Sourced from `policies/trust/revocations.txt` inside the protected repository tree.
3. **Expected Repository Identity**: Fixed to runner context `${{ github.repository }}`.
4. **Expected Workflow Identity**: Fixed to canonical platform workflow `reusable-tf-plan.yml`.
5. **Production Signing Authorization**: Requires explicit `signing_tier: "production"` and enrollment in `PLATFORM_PRODUCTION_SIGNERS`.
6. **Approval Gate Configuration**: Bound to GitHub Environment `production-approval` with required reviewers.

---

## 4. Signing Identity Separation: Preview vs. Production

InfraFlow enforces a strict cryptographic boundary between **Preview Signers** and **Production Signers**:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   SIGNING IDENTITY TRUST SEPARATION                    │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  [1] PREVIEW SIGNING IDENTITY                                          │
│      - Tier: `signing_tier: "preview"`                                 │
│      - Scope: Speculative Pull Request plans                           │
│      - Key Source: Ephemeral runner keypair (${RUNNER_TEMP})           │
│      - Authority: Validates PR step summaries and change analysis      │
│      - Restriction: STRICTLY REJECTED by Production Approval Gates     │
│                                                                        │
│  [2] PRODUCTION SIGNING IDENTITY                                       │
│      - Tier: `signing_tier: "production"`                              │
│      - Scope: Protected branch deployments / post-merge applies        │
│      - Key Source: Protected Cloud KMS / GitHub Org Secret             │
│      - Fingerprint: Enrolled in `PLATFORM_PRODUCTION_SIGNERS`          │
│        (`3c27ef9e1e520fd8c6c04db2c19680e16cf3c95a72b5536a9cada0588...`) │
│      - Authority: Sole identity authorized for production apply        │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

> [!CAUTION]
> **Ephemeral Key Limitation**: An ephemeral signing key can produce a mathematically valid digital signature, but it conveys **zero production trust**. Ephemeral preview keys must never be accepted as production-authorized signers.

### 4.1 Key Lifecycle Procedures

1. **Key Generation**:
   ```bash
   python3 scripts/verify-plan-integrity.py generate-keypair \
     --private-key signer.key \
     --public-key signer.pub
   ```
   Enforces file permission `600` on private key creation.

2. **Secure Storage**:
   - Production private keys reside exclusively in Cloud KMS (AWS KMS, Azure Key Vault, Google Cloud KMS) or GitHub Encrypted Organization Secrets (`INFRAFLOW_SIGNING_KEY`).
   - Private key bytes are NEVER committed to git or printed to workflow logs.

3. **Key Rotation**:
   - Generate a new keypair and compute its fingerprint:
     ```bash
     python3 scripts/verify-plan-integrity.py compute-fingerprint --public-key new_signer.pub
     ```
   - Update `trusted-signer-keyids` across consuming workflows to include both legacy and new fingerprints during a transition period:
     ```yaml
     trusted-signer-keyids: "<legacy_fp>,<new_fp>"
     ```
   - Deploy new private key to secrets.
   - Decommission legacy key and remove legacy fingerprint from allowlist after the transition period.

4. **Key Revocation**:
   - Immediately append the compromised fingerprint to `policies/trust/revocations.txt` and `--revoked-keyids`.
   - The verifier immediately aborts execution with exit code 1 upon encountering any artifact signed by a revoked key.

5. **Disaster Recovery**:
   - In the event of total key compromise:
     1. Add compromised fingerprint to global revocation blocklist.
     2. Generate new keypair in an isolated offline environment.
     3. Update the Public Trust Anchor (`policies/trust/trusted_signer.pub`).
     4. Invalidate pending speculative plans and re-execute pipeline generation.

---

## 5. Attack Simulation Matrix (22 Total Scenarios)

The automated local validation harness in `scripts/validate-local.sh` executes 22 specific attack simulations across Sections 11 and 12:

### 5.1 Section 11: Trust Root Isolation Scenarios (Tests 11.1–11.12)
- **11.1 PR Replacing Public Key**: Fails closed on fingerprint mismatch (**PASS**).
- **11.2 PR Replacing Key Allowlist**: Fails closed on untrusted key ID (**PASS**).
- **11.3 PR Replacing Verification Script**: Fails closed on script integrity violation (**PASS**).
- **11.4 PR Modifying Signing Workflow**: Fails closed on workflow audit (**PASS**).
- **11.5 Self-Signed Attacker Key**: Rejected by anti-substitution defense (**PASS**).
- **11.6 Revoked Signing Key**: Rejected by revocation blocklist (**PASS**).
- **11.7 Wrong Repository Identity**: Rejected by repository binding check (**PASS**).
- **11.8 Wrong Workflow Identity**: Rejected by workflow isolation check (**PASS**).
- **11.9 Modified Plan Binary**: Rejected by binary SHA-256 digest check (**PASS**).
- **11.10 Modified Plan JSON**: Rejected by JSON SHA-256 digest check (**PASS**).
- **11.11 Modified Signed Provenance**: Rejected by digital signature verification (**PASS**).
- **11.12 Wrong Source Commit**: Rejected by source commit SHA binding (**PASS**).

### 5.2 Section 12: Trusted Workflow Enforcement Scenarios (Tests 12.1–12.10)
- **12.1 PR Removing Security Workflow**: Detected and rejected by workflow audit (**PASS**).
- **12.2 PR Tampering Reusable Workflow SHA**: Detected and rejected by pinning audit (**PASS**).
- **12.3 PR Supplying Attacker Fingerprint**: Rejected by production authorization gate (**PASS**).
- **12.4 PR Changing Trusted Key**: Rejected by anti-substitution defense (**PASS**).
- **12.5 PR Omitting Revocation List**: Intercepted by protected platform revocation registry (**PASS**).
- **12.6 PR Replacing Verifier Script**: Detected by toolchain integrity verification (**PASS**).
- **12.7 PR Removing Approval Environment**: Detected and rejected by workflow audit (**PASS**).
- **12.8 PR Changing Expected Repository**: Rejected by repository binding check (**PASS**).
- **12.9 Preview Signer Production Bypass**: Rejected by signing tier separation (**PASS**).
- **12.10 Missing Security Status Authorization**: Rejected by security policy gate (**PASS**).

### 5.3 Section 13: Governance & Production Attestation Architecture (Tests 13.1–13.15)
- **13.1 Governance Ruleset Schema**: Valid JSON format conforming to GitHub REST API specification (**PASS**).
- **13.2 PR Review & Stale Approval Dismissal**: Enforces PR review and invalidates approvals upon push (solo-maintainer compatible) (**PASS**).
- **13.3 Strict GitHub Actions Status Checks**: Mandates status checks from GitHub Actions (`integration_id: 15368`) (**PASS**).
- **13.4 CODEOWNERS Sensitive Path Governance**: Designates ownership for workflows, trust policies, and verifier scripts (**PASS**).
- **13.5 Non-Fast-Forward & Deletion Protection**: Blocks force pushes and deletion of protected branch (**PASS**).
- **13.6 Zero Bypass Privileges**: Verifies empty bypass list to eliminate administrative overrides (**PASS**).
- **13.7 Plan Manifest Generation**: Binds digests, repository, commit, workflow, and security decision (**PASS**).
- **13.8 Sigstore Attestation Verification**: Successfully validates authenticated Sigstore bundle and manifest (**PASS**).
- **13.9 Tampered Manifest Rejection**: Rejects altered manifests due to subject digest mismatch (**PASS**).
- **13.10 Cross-Repository Spoofing Defense**: Rejects attestations signed by unauthorized repositories (**PASS**).
- **13.11 Insecure Plan Authorization Block**: Rejects attestations with non-passed security policy decisions (**PASS**).
- **13.12 Missing Production Attestation Defense**: Fails closed when required Sigstore attestation is missing (**PASS**).
- **13.13 OIDC Least-Privilege Verification**: Enforces `actions/attest` with `id-token: write` and zero hardcoded secrets (**PASS**).
- **13.14 Plan Job Permission Isolation**: Verifies plan job executes strictly with `contents: read` only (**PASS**).
- **13.15 Attest Job Token Isolation & Validation**: Verifies attest job isolates elevated tokens and validates manifest before attesting (**PASS**).

---

## 6. Remote Branch Protection vs. Local Guard Separation

> [!WARNING]
> **Operational Reality**:
> - **Local Workflow Branch-Guard Tests**: Verify that workflow guard logic rejects illegal paths, invalid SemVer, and commit mismatches. Verified 100% locally by `validate-local.sh` (130 checks).
> - **Remote GitHub Branch Protection**: Rules enforced on GitHub (`Require pull request reviews before merging`, `Require status checks to pass`, `Do not allow bypassing`).
> - Local offline test scripts **cannot** execute or verify live remote GitHub branch protection. Remote branch protection and rulesets are accurately documented as **UNVERIFIED (Requires live GitHub repository branch protection setup)**.

---

## 7. Schema-Aware Sensitive Attribute Protection

The **Plan Analysis Engine** (`scripts/analyze-plan.py`) implements automated recursive redaction respecting Terraform plan JSON schema trees alongside heuristic regex pattern matching.

### 7.1 Respecting `before_sensitive` and `after_sensitive`
Terraform provider schemas explicitly flag sensitive attributes in boolean trees under `change.before_sensitive` and `change.after_sensitive`. InfraFlow traverses the `after_sensitive` tree and redacts values to `(sensitive value redacted)` even for non-obvious attribute keys.

### 7.2 Sensitive Output Protection (`output_changes`)
Sensitive outputs are automatically detected via `after_sensitive` and masked to `(sensitive output redacted)` in both Markdown summaries and metrics JSON.

### 7.3 Tested Sensitive Fields & Coverage Limitations
InfraFlow combines schema-driven inspection with regex heuristics to sanitize change summaries and metrics:
- **Tested Sensitive Fields**:
  - Regex pattern: `password`, `secret`, `token`, `key`, `credential`, `private`, `cert`, `auth` (case-insensitive).
  - Schema-tagged attributes: nested maps, lists, and primitives flagged with `before_sensitive: true` or `after_sensitive: true` by provider schemas (including non-obvious attribute keys such as `custom_connection_string`).
  - Plan outputs: attributes in `output_changes` flagged with `after_sensitive: true`.
- **Coverage Limitations**:
  - **Unflagged Provider Attributes**: If a Terraform provider schema omits `sensitive = true` on an attribute whose name does not match `SENSITIVE_KEY_PATTERN`, the attribute value will not be redacted.
  - **Unstructured Text & Custom Scripts**: Free-form script blocks (e.g. `user_data`, provisioner inline shell scripts, custom IAM policy documents, raw configuration blobs) are not scanned for entropy or arbitrary embedded credentials.
  - **Non-Standard Field Names**: Secrets stored in generic attribute names (e.g. `payload`, `header_value`, `salt`, `parameter_data`) without provider schema sensitivity flags are not caught by regex heuristics alone.
  - **Pre-Analysis Plan Access**: Redaction protects public GitHub Step Summaries and published metrics JSON; raw plans residing in memory or temporary runner storage prior to cleanup remain unredacted.

---

## 8. Ephemeral Storage & Zero-Leakage Artifact Policy

| Artifact Name | Published Publicly? | Contents | Sensitivity |
|---|---|---|---|
| `plan-manifest.json` | **Yes** | Sanitized plan manifest binding digests and metadata | Public / Safe |
| `plan-provenance.json` | **Yes** | Signed DSSE in-toto provenance statement (offline compat) | Public / Safe |
| `public-key.pem` | **Optional** | Ephemeral public key (Verifier uses independent trust root) | Public / Safe |
| `plan-summary.md` | **Yes** | Sanitized Markdown change table | Public / Safe |
| `plan-metrics.json` | **Yes** | Aggregated change counts and resource addresses | Public / Safe |
| `tfplan` (raw binary) | **NO** | Raw Terraform binary execution plan | Confidential (High Risk) |
| `tfplan.json` (raw JSON) | **NO** | Full unmasked Terraform configuration & state | Confidential (High Risk) |

> [!CAUTION]
> **Zero Raw Plan Exposure**: Public GitHub repositories expose workflow artifacts to anyone on the internet. InfraFlow strictly disallows uploading raw `tfplan` binaries or raw `tfplan.json` files as build artifacts. All raw plans are deleted via exit traps and pre-upload purges.

### 8.1 Attestation Scope vs. Exact-Plan Application (Future G06 Requirement)
- **Attestation Scope**: GitHub Artifact Attestation attests `plan-manifest.json`, which contains the cryptographic SHA-256 digests of the binary `tfplan` and `tfplan.json`, along with execution metadata (repo, commit, workflow, run ID, and `security_decision: passed`).
- **Binary Plan Non-Retention**: In accordance with the zero-leakage artifact policy for public repositories, the original binary plan file (`tfplan`) and raw plan JSON (`tfplan.json`) are immediately purged from the runner and are **not** retained as downloadable artifacts.
- **No Claim of Exact-Plan Application**: Because the raw binary plan is not stored or transferred to downstream jobs, the current G04 architecture **does not enable exact-plan application** (i.e. running `terraform apply <tfplan>` using the speculative plan binary). The attestation proves the authenticity of the plan evaluation and policy compliance at planning time, not the persistence of an executable binary plan.
- **Future Milestone G06 Requirement**: In protected apply and deployment milestones (**Milestone G06 — Protected Apply & Destroy**), exact-plan application will require:
  1. An encrypted artifact persistence store (e.g., OIDC-authenticated AWS S3, Google Cloud Storage, or Azure Blob Storage with customer-managed KMS envelope encryption).
  2. Cryptographic digest verification before apply: downloading the encrypted binary plan, computing its SHA-256 digest, and verifying that it matches the attested `plan_file_sha256` in `plan-manifest.json` before executing `terraform apply`.

---

## 9. Finalized Production Architecture (G04.1.4)

### 9.1 Governance Architecture: Personal vs. Enterprise
- **Current Personal Repositories**: Protected via repository-level rulesets ([.github/rulesets/main-ruleset.json](file:///home/tharuka/projects/infraflow/.github/rulesets/main-ruleset.json)) on `TM-threemavithana/infraflow` and `TM-threemavithana/infraflow-consumer-test`. Enforces PR reviews, stale review dismissals, strict branch up-to-date checks, force push blocks, branch deletion blocks, and mandatory status checks.
- **CODEOWNERS Limitations**: [.github/CODEOWNERS](file:///home/tharuka/projects/infraflow/.github/CODEOWNERS) provides code ownership metadata and automated review routing. In a solo-maintainer environment (`required_approving_review_count: 0`, `require_code_owner_review: false`), CODEOWNERS does **not** enforce independent review or approval; independent approval requires another trusted maintainer.
- **Enterprise Adoption Path**: Documented transition to organization-level rulesets and centrally controlled required workflows when deploying to GitHub Organizations with Team/Enterprise plans ($0 budget preserved; no plans purchased).

### 9.2 Attestation Permission Isolation (Job Separation)
GitHub Actions permissions are workflow- and job-scoped, not step-scoped. To enforce true least-privilege isolation:
- **`plan` Job**:
  - Granted `permissions: contents: read` ONLY.
  - Executes Terraform CLI, `analyze-plan.py`, Trivy scanner, and Conftest OPA policies.
  - Generates sanitized `plan-manifest.json` and purges raw plan binaries and JSON.
  - Zero access to OIDC `id-token` or `attestations` write tokens.
- **`attest` Job**:
  - Isolated runner executed only after `plan` passes all security gates.
  - Granted `contents: read`, `id-token: write`, `attestations: write`.
  - Downloads only the sanitized manifest artifact (`infraflow-plan-manifest`).
  - Pre-validates manifest metadata, commit SHA binding, and policy passing status before invoking `actions/attest`.
  - Never executes untrusted Terraform code and never receives cloud credentials.
- **`verify-attestation` Job**:
  - Granted `contents: read` ONLY. No environment protection (executes before human reviewer pause).
  - Cryptographically verifies GitHub Artifact Attestation using official `gh attestation verify` via `scripts/verify-plan-integrity.py verify-attestation`.
- **`approval-gate` Job**:
  - Granted `contents: read` ONLY. Targets `environment: production-approval`.
  - Dependent on `needs.verify-attestation.result == 'success'`. Pauses for authorized human reviewers only after machine verification passes.

### 9.3 Production Signing: GitHub Artifact Attestations (Sigstore OIDC)
- **Authoritative Production Identity**: GitHub Artifact Attestations (`actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2`) with Sigstore OIDC.
- **Short-Lived Ephemeral Certificates**: Eliminates the risk of long-lived private key leaks in GitHub Secrets. Fulcio issues short-lived signing certificates bound to workflow OIDC claims, recorded in Rekor.
- **Live Workflow Isolation**: Custom ECDSA private keys are NOT required or used in the live planning workflow. Speculative planning creates the canonical `plan-manifest.json` as the attestation subject.
- **Legacy / Offline Decoupling**: ECDSA NIST P-256 in-toto DSSE asymmetric signing is retained solely for offline unit testing, attack simulation suites, and air-gapped verification. It is strictly excluded from authorizing live production approval gates (`--require-production-signer` rejects offline bundles).

### 9.4 Pre-Approval Attestation Verification
- **Cryptographic Attestation Verification**: Executed in dedicated `verify-attestation` job prior to human approval. Invokes official `gh attestation verify` to verify:
  1. **Manifest Subject Digest**: SHA-256 digest of `plan-manifest.json`.
  2. **Expected Source Repository**: Caller repository identity (`--repo`).
  3. **Expected Source Commit SHA**: Source commit binding (`--source-digest`).
  4. **Expected Signer Workflow**: Reusable planning workflow (`--signer-workflow`).
  5. **GitHub Actions OIDC Issuer**: `https://token.actions.githubusercontent.com`.
  6. **Manifest Security Decision**: Mandatory `security_decision == "passed"`.
- **Human Governance Gate**: Managed independently via GitHub Protected Environments (`environment: production-approval`). Pauses for review only if cryptographic verification succeeds; failed or missing attestations strictly block approval.

### 9.5 External Consumer Independence & Platform Toolchain Isolation (G04 PR Correction)
- **Decoupled Toolchain Architecture**: External consumer repositories invoking InfraFlow reusable workflows (`reusable-tf-security.yml`, `reusable-tf-plan.yml`) retain their application Terraform source code in `GITHUB_WORKSPACE`. InfraFlow platform tooling (scripts, policies, TFLint configuration, Zizmor configuration, and verification anchors) is checked out independently to `${RUNNER_TEMP}/infraflow-platform` via immutable commit SHA or release reference.
- **Zero Consumer Bleed**: Consumers are never required to copy platform scripts (`scripts/`), OPA policies (`policies/`), or lint configs (`.tflint.hcl`, `.zizmor.yml`) into their own repositories.
- **Fail-Closed Policy Enforcement**: If policy evaluation is enabled (`enable-policy-evaluation: true`) and the resolved policy directory is missing, both reusable workflows fail closed immediately (`exit 1`). Missing policies are strictly prohibited from degrading to warning-only success.
- **Official Production Attestation Verification**: Workflows invoke official `gh attestation verify` in GitHub Actions to cryptographically verify Sigstore OIDC Fulcio certificates, Rekor transparency logs, and subject digests. Synthetic Sigstore bundles are maintained exclusively for offline unit testing.
- **Fail-Safe Ephemeral Cleanup**: Binary plans (`tfplan`), raw plan JSON (`tfplan.json`), and temporary directories are trapped on `EXIT` and deleted in `always()` steps on both job success and job failure.