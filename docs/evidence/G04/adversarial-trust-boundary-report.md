# InfraFlow G04 — Adversarial Trust-Boundary Security Verification Report

**Document ID:** `INFRAFLOW-EVI-G04-SEC-001`
**Date:** 2026-11-20
**Target Platform:** `TM-threemavithana/infraflow` (`release/g04-platform-engine` @ `86c05e54fbf7ba1f470d4b6e2bd3f1c9a384a2f2`)
**External Consumer:** `TM-threemavithana/infraflow-consumer-test` (`test/g04-smoke-test` @ `f90d118`)
**Platform Working Tree Status:** Uncommitted Remediations & Untracked Evidence Pending Staging
**Consumer Working Tree Status:** Clean
**Classification:** Internal Technical Audit & DevSecOps Verification
**Author:** AI DevSecOps Engine (Verified Policy Gate Verification Agent)
**Status:** ✅ **PASSED (32/32 Scenarios Verified Within Defined Scope)**

---

## 1. Executive Summary & Threat Model

### 1.1 Objective
This verification report documents the adversarial security evaluation of the **InfraFlow G04 Platform Engine**. Following the completion of the trusted platform toolchain remediation and subsequent targeted refactoring, this evaluation subjects the platform's trust boundary to simulated and empirical adversarial conditions.

The objective is to verify that an external consumer repository cannot manipulate, bypass, substitute, or deceive the trusted InfraFlow governance engine via supported workflow interfaces, runner environment variables, or mutable Git references.

### 1.2 Trust Model & Boundaries
The InfraFlow governance model operates across a defined trust boundary separating the **Platform** from the **Consumer**:

```
+-----------------------------------------------------------------------------------+
|                            UNTRUSTED CONSUMER SPACE                               |
|  - Consumer Repository (TM-threemavithana/infraflow-consumer-test)                |
|  - Consumer Terraform code, local modules, variables                              |
|  - Consumer Workflow caller (.github/workflows/infraflow-smoke-test.yml)          |
|  - Consumer-controlled environment variables, repo files (.trivyignore, etc.)     |
+-----------------------------------------------------------------------------------+
                                       |
                   [ Invokes Reusable Workflow via workflow_call ]
                   [ Passing strictly validated parameters only ]
                   [ Pinned to exact 40-character commit SHA ]
                                       |
                                       v
+-----------------------------------------------------------------------------------+
|                             TRUSTED PLATFORM ENGINE                               |
|  - Pinned Workflow: TM-threemavithana/infraflow/.github/workflows/reusable-tf-plan |
|  - Validated Reference: job.workflow_ref (@<40-char-hex-SHA> strictly enforced)   |
|  - Resolved Commit: job.workflow_sha (86c05e5...)                                 |
|  - Trusted Repo Context: job.workflow_repository (TM-threemavithana/infraflow)    |
|  - Isolated Checkout Path: ${RUNNER_TEMP}/infraflow-platform                      |
|  - Toolchain Scripts: scripts/analyze-plan.py, scripts/verify-plan-integrity.py   |
|  - Security Policies: policies/*.rego (Enforced OPA & Trivy rule sets)            |
|  - Cryptographic Provenance: Sigstore Keyless GitHub Artifact Attestation         |
|  - Attestation Signer Binding: --signer-workflow & --signer-digest enforced      |
|  - Authorization Gate: Automated Verified Policy Gate (Zero human-spoofing)      |
+-----------------------------------------------------------------------------------+
```

### 1.3 STRIDE Threat Analysis

| Threat Category | Potential Attack Vector | InfraFlow Mitigation Mechanism |
| :--- | :--- | :--- |
| **Spoofing** | Attacker specifies rogue repo, mutable branch ref, or fake signer identity | Platform caller interface excludes repo inputs; runtime guard validates `job.workflow_repository == TM-threemavithana/infraflow`; `job.workflow_ref` validates 40-char SHA matching `job.workflow_sha`; Sigstore verifies exact OIDC signer workflow and `--signer-digest`. |
| **Tampering** | Consumer modifies plan JSON, binary plan, or bypasses scanners via `.trivyignore` | Manifest binds SHA-256 digests of plan JSON & binary; CLI wrapper purges `TRIVY_*` env and enforces `--ignorefile ""`. |
| **Repudiation** | Attacker generates invalid or synthetic attestations | Official Sigstore verification (`gh attestation verify`) validates transparency log signatures anchored in GitHub Fulcio/Rekor root. |
| **Information Disclosure** | Leakage of sensitive secrets or suppression of findings | High/Critical severities hardcoded in platform workflow; scan reports isolated in runner temp. |
| **Denial of Service** | Corrupted inputs causing unhandled exceptions | Fail-closed shell scripting (`set -euo pipefail`), comprehensive schema validation in Python scripts. |
| **Elevation of Privilege** | Bypassing failing security scans to authorize destructive or insecure apply | Verified Policy Gate requires strict `success` outcomes across all jobs (`plan`, `attest`, `verify-attestation`); rejects destructive plans unless explicit flag set. |

---

## 2. Adversarial Test Scenarios (A through F)

### Scenario A: Platform Repository Substitution
* **Attacker Objective:** Force the reusable workflow to execute platform tooling from an attacker-controlled GitHub repository containing modified scripts or weakened security policies.
* **Attack Vectors:**
  1. Consumer provides an unauthorized `platform-repository` input to `reusable-tf-plan.yml`.
  2. Consumer runs the reusable workflow from a forked or rogue repository (`attacker-org/rogue-infraflow`).
* **Implemented Mitigation:**
  - Removed `platform-repository` and `platform-ref` inputs from `workflow_call.inputs`.
  - Added runtime guard step validating `job.workflow_repository == "TM-threemavithana/infraflow"`.
* **Test Evidence:**
  - `A.1`: Static AST verification confirmed that `platform-repository` is absent from `workflow_call.inputs` across all platform workflows (**PASS**).
  - `A.2`: Guard script dynamically simulated with `WORKFLOW_REPO="attacker-org/rogue-infraflow"` exited 1 with exact error output (**PASS**).

---

### Scenario B: Platform Commit & Workflow Reference Substitution
* **Attacker Objective:** Provide a mutable branch name (`main`), mutable tag (`v0.1.0`), short commit SHA, or mismatched commit ref to downgrade platform tooling or introduce backdoors.
* **Important Technical Insight:** In GitHub Actions, `job.workflow_sha` is *already resolved* to a commit SHA by GitHub's orchestrator, even when the caller invokes the workflow using a branch name (`@main`) or tag (`@v0.1.0`). Therefore, validating only `job.workflow_sha` against a hex regex is insufficient to guarantee caller immutability.
* **Implemented Mitigation:**
  - Replaced single-SHA check with strict validation of `job.workflow_ref`:
    ```bash
    WORKFLOW_REF_PREFIX="${WORKFLOW_REF%@*}"
    WORKFLOW_REF_TARGET="${WORKFLOW_REF##*@}"
    EXPECTED_PREFIX="${TRUSTED_PLATFORM_REPO}/${EXPECTED_WORKFLOW_PATH}"

    # Verify workflow path prefix
    if [[ "${WORKFLOW_REF_PREFIX}" != "${EXPECTED_PREFIX}" ]]; then
      exit 1
    fi

    # Reject mutable references (@main, @refs/heads/..., @v..., @refs/tags/...) and short SHAs
    if [[ ! "${WORKFLOW_REF_TARGET}" =~ ^[0-9a-fA-F]{40}$ ]]; then
      exit 1
    fi

    # Verify reference SHA strictly matches resolved workflow SHA
    if [[ "${WORKFLOW_REF_TARGET}" != "${WORKFLOW_SHA}" ]]; then
      exit 1
    fi
    ```
* **Test Evidence & Analysis:**
  - `B.1`: Static inspection confirmed `job.workflow_repository`, `job.workflow_sha`, and `job.workflow_ref` bound across checkouts and guards (**PASS**).
  - `B.2`: Guard rejected `@main` in `job.workflow_ref` (exit 1) (**PASS**).
  - `B.3`: Guard rejected `@refs/heads/main` in `job.workflow_ref` (exit 1) (**PASS**).
  - `B.4`: Guard rejected `@v0.1.0` in `job.workflow_ref` (exit 1) (**PASS**).
  - `B.5`: Guard rejected `@refs/tags/v0.1.0` in `job.workflow_ref` (exit 1) (**PASS**).
  - `B.6`: Guard rejected short SHA `@86c05e5` in `job.workflow_ref` (exit 1) (**PASS**).
  - `B.7`: Guard rejected mismatched SHA (`@1111...` vs `86c0...`) in `job.workflow_ref` (exit 1) (**PASS**).
  - `B.8`: Guard rejected rogue workflow path prefix in `job.workflow_ref` (exit 1) (**PASS**).
  - `B.9`: Guard accepted valid full 40-character commit SHA reference matching `job.workflow_sha` (exit 0) (**PASS**).
  - `B.10`: Empirical Git Server Boundary Observation (Run `44683936446`): GitHub remote git server returned `remote error: upload-pack: not our ref 59712f845...` when attempting to fetch a foreign caller commit into the platform repository (**PASS**).

---

### Scenario C: Attestation Signer Forgery & Digest Verification
* **Attacker Objective:** Forge an attestation bundle, generate fake provenance, tamper with signed plan payloads, or use an attestation produced by an unauthorized signer repository/workflow.
* **Attestation Certificate Analysis:**
  Inspection of the live Sigstore X.509 certificate generated during consumer Run `44684508073` reveals that GitHub Artifact Attestation embeds:
  - `buildSignerURI`: `https://github.com/TM-threemavithana/infraflow/.github/workflows/reusable-tf-plan.yml@86c05e54fbf7ba1f470d4b6e2bd3f1c9a384a2f2`
  - `buildSignerDigest`: `86c05e54fbf7ba1f470d4b6e2bd3f1c9a384a2f2`
  - `sourceRepositoryURI`: `https://github.com/TM-threemavithana/infraflow-consumer-test`
* **Official CLI Flag Behavior:**
  In `gh attestation verify`, flags in the group `[cert-identity, cert-identity-regex, signer-repo, signer-workflow]` are mutually exclusive. Passing `--signer-workflow` and `--signer-digest` simultaneously is supported and enforces both the exact workflow path and the exact commit SHA of the reusable workflow.
* **Implemented Mitigation:**
  - Added `--signer-digest` parameter support to `scripts/verify-plan-integrity.py`.
  - Updated `reusable-tf-plan.yml` to pass `--signer-digest "${{ job.workflow_sha }}"`.
* **Test Evidence (Evaluated Against Real Attestation Artifact from Run 44684508073):**
  - `C.1`: Verification rejected unauthorized repository identity in manifest (exit 1) (**PASS**).
  - `C.2`: Verification rejected mismatched source commit SHA in manifest (exit 1) (**PASS**).
  - `C.3`: Verification rejected mismatched workflow identity in manifest (exit 1) (**PASS**).
  - `C.4`: Verification rejected tampered plan JSON digest (exit 1) (**PASS**).
  - `C.5a`: Official `gh attestation verify` with correct signer workflow and exact signer digest (`86c05e5...`) succeeded (exit 0) (**PASS**).
  - `C.5b`: Official `gh attestation verify` with incorrect signer repo (`attacker-org/rogue-infraflow`) rejected with Sigstore certificate mismatch (exit 1) (**PASS**).
  - `C.5c`: Official `gh attestation verify` with incorrect signer workflow (`.../rogue-workflow.yml`) rejected with Sigstore certificate mismatch (exit 1) (**PASS**).
  - `C.5d`: Official `gh attestation verify` with incorrect signer digest (`0000000...`) rejected with `expected BuildSignerDigest to be 0000..., got 86c0...` (exit 1) (**PASS**).

---

### Scenario D: Security Gate Bypass
* **Attacker Objective:** Manipulate workflow dependencies or status parameters to achieve `auth-status=authorized` despite failing scans or uninspected destructive changes.
* **Implemented Mitigation:**
  - Gate authorization evaluation requires:
    ```bash
    if [[ "$PLAN_STATUS" == "success" && \
          "$TRIVY_STATUS" == "success" && \
          "$CONFTEST_STATUS" == "success" && \
          "$ATTEST_STATUS" == "success" && \
          "$VERIFY_STATUS" == "success" && \
          "$DESTRUCTIVE_DECISION" == "allowed" ]]; then
      AUTH_STATUS="authorized"
    else
      AUTH_STATUS="rejected"
    fi
    ```
* **Test Evidence:**
  - `D.1` to `D.5`: Every individual failure/skip condition dynamically evaluated to `AUTH_STATUS=rejected` and exit 1 (**PASS**).
  - `D.6`: Destructive plan with `fail-on-destructive=true` dynamically evaluated to `AUTH_STATUS=rejected` and exit 1 (**PASS**).
  - `D.7`: Static AST workflow inspection verified `verified-policy-gate` strictly requires `[plan, attest, verify-attestation]` (**PASS**).

---

### Scenario E: Consumer-Controlled Security Configuration
* **Attacker Objective:** Provide repository-level configuration files (`.trivyignore`, `trivy.yaml`) or environment variables (`TRIVY_SEVERITY=LOW`, `TRIVY_EXIT_CODE=0`) to suppress findings and bypass the security gate.
* **Implemented Mitigation:**
  - Platform wrapper purges all `TRIVY_*` environment variables in a loop and unsets `XDG_CACHE_HOME`.
  - Platform dynamically writes a pristine configuration to `${RUNNER_TEMP}/infraflow-trivy.yaml` enforcing `ignorefile: ""` and `scanners: [terraform]`.
  - Platform invokes CLI with explicit CLI overrides: `--config "${TRIVY_CONF}" --cache-dir "${TRIVY_CACHE}" --ignorefile "" --severity "HIGH,CRITICAL" --exit-code 1`.
* **Test Evidence:**
  - `E.1`: Tested platform wrapper against an insecure S3 bucket (`acl = "public-read"`) accompanied by a malicious `.trivyignore` (`*`), malicious `trivy.yaml`, and `TRIVY_SEVERITY=LOW`. The platform wrapper successfully purged the environment, ignored the ignorefile, detected 6 HIGH misconfigurations, and exited 1 (**PASS**).

---

### Scenario F: Manifest and Plan Integrity
* **Attacker Objective:** Tamper with metadata inside `plan-manifest.json`, inject unsupported schema versions, or alter the candidate binary plan file prior to verification.
* **Implemented Mitigation:**
  - `verify-plan-integrity.py` validates that `metadata.security_decision == "passed"`.
  - Strict schema enforcement requires `schema_version == "infraflow-plan-manifest-v1"`.
  - Binary plan digest check compares computed `sha256(plan_file)` against `manifest.digests.plan_file_sha256`.
* **Test Evidence:**
  - `F.1`: Dynamic CLI execution rejected `security_decision: failed` with exit 1 (**PASS**).
  - `F.2`: Dynamic CLI execution rejected schema `invalid-v999` with exit 1 (**PASS**).
  - `F.3`: Dynamic CLI execution rejected tampered binary digest with exit 1 (**PASS**).
  - `F.4`: Dynamic CLI execution rejected tampered plan JSON digest with exit 1 (**PASS**).

---

## 3. Comprehensive Verification Matrix & Platform Quality Gates

### 3.1 Automated Platform Verification Suite (8 Quality Gates)

Prior to publication and external consumer integration, the platform undergoes comprehensive validation across 8 automated quality gates (185 automated tests in `scripts/validate-local.sh` and 7 external validation linters/engines):

| Gate # | Quality Gate Layer | Tool / Engine | Target / Scope | Result |
| :---: | :--- | :--- | :--- | :---: |
| **1** | Local Regression Harness | `scripts/validate-local.sh` | 185 automated checks across G01–G04.1.4 (including trust boundary 14.45–14.53) | **185 / 185 PASS** |
| **2** | GitHub Actions Workflow Linter | `actionlint` (v1.7.7) | `.github/workflows/*.yml`, consumer templates | **0 errors** |
| **3** | Shell Script Static Linter | `shellcheck` (v0.10.0) | `scripts/*.sh` | **0 warnings** |
| **4** | Rego Policy Verification Engine | `conftest verify` (v0.71.1) | 62 enterprise Rego unit tests in `policies/` | **62 / 62 PASS** |
| **5** | GitHub Actions Security Auditor | `zizmor` (v1.32.0) | Reusable workflows, runner permissions, injection audits | **0 findings** |
| **6** | Secrets & Credential Detection | `gitleaks` (v8.30.1) | Full platform workspace | **0 leaks** |
| **7** | Python Compilation & Syntax | `python3 -m py_compile` | `scripts/analyze-plan.py`, `scripts/verify-plan-integrity.py` | **0 errors** |
| **8** | Git Diff & Whitespace Verification | `git diff --check` | Working tree whitespace, formatting, merge markers | **Clean** |

### 3.2 Adversarial Test Matrix (32 Scenarios)

The adversarial test suite consists of 32 test cases categorized across four verification methodologies:
- **Static Inspection (3 tests):** Static analysis of workflow AST and YAML structures.
- **Local Dynamic Simulation (15 tests):** Live execution of shell guard, reference parsing, and policy gate logic with mock inputs.
- **Local Dynamic Tool Execution (13 tests):** Live execution of Python scripts, Trivy binary, and official GitHub CLI against real fixtures and authentic Sigstore artifacts.
- **Live CI Empirical Observation (1 test):** Empirical observation from live GitHub Actions infrastructure.

| Test ID | Scenario | Test Case Description | Verification Method | Exit Code (Obs/Exp) | Status | Observed Output Evidence |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **A.1** | Scenario A | Caller input interface excludes `platform-repository` | Static Inspection | `0 / 0` | **PASS** | `platform-repository input removed from workflow_call schemas` |
| **A.2** | Scenario A | Runtime guard step rejects rogue workflow repository | Local Dynamic Simulation | `1 / 1` | **PASS** | `::error::Security Violation: Platform workflow repository 'attacker-org/rogue-infraflow' is not...` |
| **B.1** | Scenario B | Checkouts and guards strictly bind to repository, sha, and ref | Static Inspection | `0 / 0` | **PASS** | `Found 3 workflow_repository checkouts, 3 workflow_sha refs, WORKFLOW_REF bound in guard` |
| **B.2** | Scenario B | Guard rejects mutable branch ref `@main` in `job.workflow_ref` | Local Dynamic Simulation | `1 / 1` | **PASS** | `::error::Security Violation: Caller workflow reference 'main' is not a valid immutable 40-character commit SHA.` |
| **B.3** | Scenario B | Guard rejects mutable branch ref `@refs/heads/main` in `job.workflow_ref` | Local Dynamic Simulation | `1 / 1` | **PASS** | `::error::Security Violation: Caller workflow reference 'refs/heads/main' is not a valid immutable...` |
| **B.4** | Scenario B | Guard rejects mutable release tag `@v0.1.0` in `job.workflow_ref` | Local Dynamic Simulation | `1 / 1` | **PASS** | `::error::Security Violation: Caller workflow reference 'v0.1.0' is not a valid immutable...` |
| **B.5** | Scenario B | Guard rejects mutable release tag `@refs/tags/v0.1.0` in `job.workflow_ref` | Local Dynamic Simulation | `1 / 1` | **PASS** | `::error::Security Violation: Caller workflow reference 'refs/tags/v0.1.0' is not a valid...` |
| **B.6** | Scenario B | Guard rejects short commit SHA `@86c05e5` in `job.workflow_ref` | Local Dynamic Simulation | `1 / 1` | **PASS** | `::error::Security Violation: Caller workflow reference '86c05e5' is not a valid immutable...` |
| **B.7** | Scenario B | Guard rejects caller reference SHA mismatched with resolved `workflow_sha` | Local Dynamic Simulation | `1 / 1` | **PASS** | `::error::Security Violation: Caller workflow reference SHA '1111...' does not match resolved...` |
| **B.8** | Scenario B | Guard rejects caller referencing unexpected workflow path prefix | Local Dynamic Simulation | `1 / 1` | **PASS** | `::error::Security Violation: workflow_ref prefix '.../rogue-workflow.yml' does not match...` |
| **B.9** | Scenario B | Guard accepts valid 40-char SHA reference matching `workflow_sha` | Local Dynamic Simulation | `0 / 0` | **PASS** | Clean execution with exit code 0 |
| **B.10** | Scenario B | Live Git Server rejects fetching commit not present in platform repo | Live CI Empirical Observation | `128 / 128` | **PASS** | `remote error: upload-pack: not our ref 59712f845...` (Live Run 44683936446). |
| **C.1** | Scenario C | Manifest verification rejects unauthorized repository identity | Local Dynamic Tool Execution | `1 / 1` | **PASS** | `Repository mismatch: manifest recorded 'TM-threemavithana/infraflow', expected 'attacker-org/rogue-repo'` |
| **C.2** | Scenario C | Manifest verification rejects mismatched source commit SHA | Local Dynamic Tool Execution | `1 / 1` | **PASS** | `Commit SHA mismatch: manifest recorded '86c05e5...', expected '0000000...'` |
| **C.3** | Scenario C | Manifest verification rejects mismatched workflow identity | Local Dynamic Tool Execution | `1 / 1` | **PASS** | `Workflow mismatch: manifest recorded 'reusable-tf-plan.yml', expected 'attacker-injected-workflow.yml'` |
| **C.4** | Scenario C | Manifest verification rejects tampered plan JSON digest | Local Dynamic Tool Execution | `1 / 1` | **PASS** | `CRITICAL: Plan JSON digest mismatch! Candidate plan does not match manifest.` |
| **C.5a** | Scenario C | Official `gh attestation verify` PASS with correct signer workflow & digest | Local Dynamic Tool Execution | `0 / 0` | **PASS** | Clean verification against real artifact and Rekor transparency log (Run 44684508073) |
| **C.5b** | Scenario C | Official `gh attestation verify` REJECTS unauthorized signer repo | Local Dynamic Tool Execution | `1 / 1` | **PASS** | `Error: verifying with issuer "sigstore.dev"` (SAN certificate issuer/signer mismatch) |
| **C.5c** | Scenario C | Official `gh attestation verify` REJECTS unauthorized signer workflow | Local Dynamic Tool Execution | `1 / 1` | **PASS** | `Error: verifying with issuer "sigstore.dev"` (SAN workflow path mismatch) |
| **C.5d** | Scenario C | Official `gh attestation verify` REJECTS mismatched signer commit digest | Local Dynamic Tool Execution | `1 / 1` | **PASS** | `Error: expected BuildSignerDigest to be 00000000..., got 86c05e54...` |
| **D.1** | Scenario D | Verified Policy Gate rejects skipped speculative plan job | Local Dynamic Simulation | `1 / 1` | **PASS** | `AUTH_STATUS=rejected` on `PLAN_STATUS=skipped` |
| **D.2** | Scenario D | Verified Policy Gate rejects failed Trivy scan | Local Dynamic Simulation | `1 / 1` | **PASS** | `AUTH_STATUS=rejected` on `TRIVY_STATUS=failure` |
| **D.3** | Scenario D | Verified Policy Gate rejects failed Conftest / OPA evaluation | Local Dynamic Simulation | `1 / 1` | **PASS** | `AUTH_STATUS=rejected` on `CONFTEST_STATUS=failure` |
| **D.4** | Scenario D | Verified Policy Gate rejects skipped Sigstore attestation generation | Local Dynamic Simulation | `1 / 1` | **PASS** | `AUTH_STATUS=rejected` on `ATTEST_STATUS=skipped` |
| **D.5** | Scenario D | Verified Policy Gate rejects failed attestation verification | Local Dynamic Simulation | `1 / 1` | **PASS** | `AUTH_STATUS=rejected` on `VERIFY_STATUS=failure` |
| **D.6** | Scenario D | Verified Policy Gate rejects destructive plan when `fail-on-destructive=true` | Local Dynamic Simulation | `1 / 1` | **PASS** | `AUTH_STATUS=rejected` on `HAS_DESTRUCTIVE=true` |
| **D.7** | Scenario D | Workflow DAG enforces gate dependency on `[plan, attest, verify-attestation]` | Static Inspection | `0 / 0` | **PASS** | DAG dependencies verified in YAML AST. |
| **E.1** | Scenario E | Trivy wrapper purges `TRIVY_*` env, overrides `.trivyignore`, detects flaw | Local Dynamic Tool Execution | `1 / 1` | **PASS** | Detected 6 HIGH misconfigurations in insecure S3 HCL despite attacker `.trivyignore` (`*`). |
| **F.1** | Scenario F | Manifest verification rejects `security_decision: failed` | Local Dynamic Tool Execution | `1 / 1` | **PASS** | `CRITICAL: Security decision in manifest was 'failed'. Only plans passing all enterprise...` |
| **F.2** | Scenario F | Manifest verification rejects invalid schema version (`invalid-v999`) | Local Dynamic Tool Execution | `1 / 1` | **PASS** | `Unsupported schema version 'invalid-v999', expected 'infraflow-plan-manifest-v1'` |
| **F.3** | Scenario F | Manifest verification rejects tampered binary plan digest | Local Dynamic Tool Execution | `1 / 1` | **PASS** | `CRITICAL: Binary plan file digest mismatch! Manifest SHA256: 111111..., Computed: fee20e...` |
| **F.4** | Scenario F | Legacy plan verification detects tampered plan JSON digest | Local Dynamic Tool Execution | `1 / 1` | **PASS** | `CRITICAL: Plan JSON digest mismatch! Expected SHA256: 683e..., Computed: 38df...` |

---

## 4. Threat Model Limitations & Consumer Protection Requirements

To maintain complete engineering honesty and avoid claiming absolute security assurance, the following explicit boundaries are documented:

### 4.1 Known Attack Surfaces & Limitations
1. **Untrusted Terraform Provider Code Execution:** In `reusable-tf-plan.yml`, `terraform init` and `terraform plan` run on the runner VM before security scanners execute. If a consumer provides an untrusted custom Terraform provider or a module containing a `local-exec` provisioner, arbitrary binary code could execute during `terraform plan`, potentially accessing `${RUNNER_TEMP}` or modifying files before attestation.
2. **OPA / Conftest Configuration Manipulation:** While Scenario E thoroughly verified Trivy isolation, adversarial bypass attempts against Conftest (such as supplying a `.conftestignore` or manipulating OPA Rego namespaces in consumer subdirectories) were not evaluated.
3. **Artifact Manipulation in Runner Storage:** GitHub Artifact Attestations are stored in GitHub's internal transparency log, but the `plan-manifest.json` file is passed between jobs via standard GitHub Actions artifact uploads (`actions/upload-artifact`). Direct manipulation of artifacts between jobs was not tested.
4. **Denial of Service via Resource Exhaustion:** Extremely large Terraform plans (e.g. multi-gigabyte JSON files) designed to cause Out-Of-Memory (OOM) failures during Python manifest generation or verification were not benchmarked.
5. **Exact-Plan Binary Application (Deferred to G06):** While the SHA-256 digest of the binary plan file is generated and validated in G04 (`plan_file_sha256`), the downstream consumption of this binary plan during `terraform apply` is deferred to milestone G06.

### 4.2 Mandatory Consumer Protection Policy
Because the platform engine enforces governance via reusable workflows, **consumers must actively protect their own caller workflow configuration**:
- **Pin to Reviewed Full Commit SHAs:** Consumers must reference InfraFlow reusable workflows using exact, reviewed 40-character commit SHAs (e.g., `uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-plan.yml@86c05e54fbf7ba1f470d4b6e2bd3f1c9a384a2f2`). The platform guard will strictly reject any caller referencing mutable branches (`@main`) or tags (`@v0.1.0`).
- **Enforce Branch Protection on Caller Repositories:** Consumers must configure GitHub branch protection rules requiring pull request reviews and status checks on their default branch. Without caller repository branch protection, an attacker with write access to the consumer repository could alter the workflow invocation directly.
- **Audit Third-Party Terraform Providers:** Consumers must ensure that only verified Terraform providers from official registries are used, preventing malicious executable code from running during speculative plan generation.

---

## 5. Final G04 Security Acceptance Recommendation

### Verdict: ✅ **GO FOR G04 RELEASE APPROVAL**

The InfraFlow platform engine has demonstrated robust defense-in-depth across all evaluated threat boundaries within the G04 milestone scope:
1. **Repository substitution** is prevented by removing caller inputs and enforced by runtime guard.
2. **Workflow reference validation** strictly rejects mutable branches (`@main`), tags (`@v0.1.0`), and short SHAs, accepting only valid 40-character commit SHAs matching `job.workflow_sha`.
3. **Attestation forgery** is prevented by Sigstore OIDC signing, cryptographic digest binding, and explicit `--signer-workflow` and `--signer-digest` verification.
4. **Security gates cannot be bypassed**; both scanners (Trivy and Conftest) and provenance verification must succeed.
5. **Consumer configuration cannot suppress findings**; declarative Trivy bypass files and environment variables are neutralized.
6. **Plan integrity is cryptographically validated** via SHA-256 manifest digests.

### Prerequisites for Merge & Milestone Closure (Awaiting User Authorization):
1. **Commit Remediations & Evidence:** Stage and commit the 5 modified platform files plus `docs/evidence/` to `release/g04-platform-engine`.
2. **Merge Platform PR #1:** Standard merge of `release/g04-platform-engine` into `main` on `TM-threemavithana/infraflow`.
3. **Release Tagging:** Create release tag `v0.2.0` pinned to the merged platform commit.
4. **Merge Consumer PR #1:** Merge `test/g04-smoke-test` into `main` on `TM-threemavithana/infraflow-consumer-test`.
5. **Clean up ephemeral scratch artifacts:** Remove temporary scratch scripts and JSON dumps.

---
*End of Report — InfraFlow G04 Adversarial Trust-Boundary Security Verification.*
