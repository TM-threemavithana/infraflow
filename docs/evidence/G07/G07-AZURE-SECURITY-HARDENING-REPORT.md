# InfraFlow — Azure Adapter Security Hardening & Adversarial Validation Report
**Milestone:** G07.6 — Azure Adapter Security Hardening and Adversarial Validation
**Date:** 2026-11-21
**Classification:** Enterprise Security Audit & Adversarial Verification Report
**Branch:** `feature/g07-azure-adapter`
**Base Commit:** `7ab3c1cc104f3ef253b8bf5b21791e8b6d4ea19c`
**Published Baseline:** `v0.4.0`
**Status:** ALL GATES PASSED (303/303 Checks Clean, 299 Python Tests, 171 Rego Tests, 45 Adversarial Vectors)
**Cloud Spend:** $0.00 (Strictly Offline & Cloud-Free)

---

## 1. Executive Summary

Milestone **G07.6: Azure Adapter Security Hardening and Adversarial Validation** conducted an independent, adversarial security assessment of the Microsoft Azure cloud-free Terraform adapter, Microsoft Entra ID Workload Identity Federation policies, and Azure Blob Storage state backend controls implemented in Milestone G07.5.

The primary objectives achieved were:
1. **Vulnerability Discovery & Remediation**: Audited all Azure adapter components, identifying and correcting 8 genuine vulnerabilities and defense-in-depth gaps across workflow guards, Rego policies, and cleanup handlers.
2. **Data Plane vs Control Plane Authentication Nuance**: Resolved a critical security subtlety in Terraform's `azurerm` backend where `use_oidc = true` alone falls back to retrieving storage account shared keys via ARM control plane, strictly mandating `use_azuread_auth = true` for data plane blob access.
3. **Repository Trust Boundary Enforcement**: Eliminated empty-string bypass risks in `reusable-tf-azure.yml` by enforcing unconditional repository origin matching (`TM-threemavithana/infraflow`) and 40-character hexadecimal `WORKFLOW_SHA` validation.
4. **Entra ID Federated Identity Credentials (FIC) Policy Hardening**: Hardened `policies/azure/entra_oidc.rego` to reject flexible FIC preview features (custom `claims` blocks), enforce `expected_repository` and `expected_repository_id` boundaries, and validate RFC 4122 GUID formats across all identity fields.
5. **Independent Adversarial Suite**: Authored `tests/test_azure_adversarial_integration.py` containing 45 comprehensive test vectors exercising identity guards, backend controls, scanner severity, and fail-closed summary aggregation.
6. **Harness Integration**: Extended Section 18 of `scripts/validate-local.sh` from 25 to 26 dedicated checks, advancing platform-wide automated checks from 302 to 303 (100% passing).
7. **Zero Cloud Expenditure & Regression Invariant**: Preserved strict $0.00 cloud spend, zero live credentials, and 100% pass rate across G01 through G07.5 regressions.

```
==============================================================================
>>> Summary of Validation Results (Milestone G07.6)
==============================================================================
Total Checks Executed : 303
Passed Checks         : 303
Failed Checks         : 0

>>> ALL G01/G02/G03/G04/G05/G06/G07 QUALITY GATES PASSED SUCCESSFULLY (303/303) <<<
```

---

## 2. Vulnerability Findings & Security Remediations

The audit identified 8 genuine security issues across workflow files and policy engines:

### Finding SEC-G07-06 (High): Repository Trust Boundary Bypass in `reusable-tf-azure.yml`
- **Location:** `.github/workflows/reusable-tf-azure.yml` (`validate-inputs` job)
- **Vulnerability:** The caller repository validation used `if [[ -n "${WORKFLOW_REPO:-}" && "${WORKFLOW_REPO}" != "${EXPECTED_PLATFORM_REPO}" ]]; then`. If `WORKFLOW_REPO` was empty or unset by a caller, the check was completely bypassed. Additionally, `WORKFLOW_SHA` was not validated against a 40-character hexadecimal regex.
- **Remediation:** Changed check to unconditional comparison: `if [[ "${WORKFLOW_REPO:-}" != "${EXPECTED_PLATFORM_REPO}" ]]` and added strict SHA validation: `if [[ ! "${WORKFLOW_SHA:-}" =~ ^[0-9a-fA-F]{40}$ ]]`.
- **Verification:** Vectors 38 and 39 in `tests/test_azure_adversarial_integration.py` and Section 18.14 in `validate-local.sh`.

### Finding SEC-G07-07 (Critical): Data Plane vs Control Plane Conflation in `azurerm` Backend
- **Location:** `policies/azure/storage_backend.rego` (Rule 5)
- **Vulnerability:** Rule 5 previously allowed `use_oidc = true` as an alternative to `use_azuread_auth = true`. However, in Terraform's `azurerm` backend architecture:
  - `use_oidc = true`: Authenticates against Azure Resource Manager (ARM) via OIDC.
  - `use_azuread_auth = true`: Mandates Entra ID data-plane authentication for Blob operations.
  - *Risk:* If `use_azuread_auth` is false while `use_oidc` is true, Terraform uses ARM to fetch the storage account shared access key and performs state operations via shared key.
- **Remediation:** Hardened Rule 5 to strictly mandate `use_azuread_auth = true` for data plane access. `use_oidc = true` alone without `use_azuread_auth = true` is explicitly rejected.
- **Verification:** Unit test `test_use_oidc_alone_without_azuread_auth_denied` and Vector 23.

### Finding SEC-G07-08 (High): Missing Repository Substitution Defense in `entra_oidc.rego`
- **Location:** `policies/azure/entra_oidc.rego` (Rule 6)
- **Vulnerability:** Rule 6 validated format syntax but did not verify that the subject repository matched `expected_repository` or `expected_repository_id` when supplied. A malicious developer in an organization could target a different repository's identity credential.
- **Remediation:** Added checks verifying that `subject` starts with `repo:<expected_repository>:` and `repo-id:<expected_repository_id>:`.
- **Verification:** Unit tests 17 and 18 in `entra_oidc_test.rego` and Vectors 17 and 18 in `test_azure_adversarial_integration.py`.

### Finding SEC-G07-09 (Medium): Permissive Flexible Federated Credentials (Preview)
- **Location:** `policies/azure/entra_oidc.rego` (Rule 6.1)
- **Vulnerability:** Microsoft Entra ID introduced "flexible federated identity credentials" (public preview) that evaluate arbitrary custom claims expressions rather than exact subject string matching. Allowing custom claims introduces non-deterministic evaluation and bypass vectors.
- **Remediation:** Implemented Rule 6.1 strictly prohibiting federated credentials that define custom `claims` blocks.
- **Verification:** Unit test 20 in `entra_oidc_test.rego` and Vector 19 in `test_azure_adversarial_integration.py`.

### Finding SEC-G07-10 (Medium): Permissive Security Severity Thresholds in Workflow
- **Location:** `.github/workflows/reusable-tf-azure.yml` (`validate-inputs` job)
- **Vulnerability:** Line 371 permitted `CRITICAL` alone as a valid severity threshold (`${INPUT_SEVERITY} != "HIGH,CRITICAL" && ${INPUT_SEVERITY} != "CRITICAL"`). This allowed consumers to suppress `HIGH` severity vulnerabilities from Trivy scans, violating InfraFlow's platform security baseline.
- **Remediation:** Updated line 371 to strictly enforce `${INPUT_SEVERITY} == "HIGH,CRITICAL"`.
- **Verification:** Vector 37 in `test_azure_adversarial_integration.py`.

### Finding SEC-G07-11 (Low): Unhandled `plan-metrics.json` in Ephemeral Cleanup Trap
- **Location:** `.github/workflows/reusable-tf-azure.yml` (`cloud-free-plan` job)
- **Vulnerability:** The cleanup trap in the planning step only cleared `tfplan` and `tfplan.json` (`trap 'rm -f tfplan tfplan.json' EXIT INT TERM`), leaving `plan-metrics.json` on disk upon unexpected job cancellation.
- **Remediation:** Extended trap and step cleanup to include `plan-metrics.json`: `trap 'rm -f tfplan tfplan.json plan-metrics.json' EXIT INT TERM`.
- **Verification:** Vector 45 in `test_azure_adversarial_integration.py`.

### Finding SEC-G07-12 (Low): RFC 4122 GUID Standards Clarification
- **Location:** `.github/workflows/reusable-tf-azure.yml` and `policies/azure/entra_oidc.rego`
- **Vulnerability:** Code comments and error messages referenced "UUIDv4", whereas Azure documentation and APIs allow any valid RFC 4122 GUID format (versions 1 through 5).
- **Remediation:** Standardized regex and error messages to explicitly reference RFC 4122 GUID.
- **Verification:** Unit test 13 in `entra_oidc_test.rego` and Vectors 2-4 in `test_azure_adversarial_integration.py`.

### Finding SEC-G07-13 (Low): Single Object `role_assignment` Input Parsing
- **Location:** `policies/azure/storage_backend.rego`
- **Vulnerability:** Helper `get_role_assignments` parsed `resource.azurerm_role_assignment` and `role_assignments` arrays, but omitted single-object `input.role_assignment`.
- **Remediation:** Added `get_role_assignments contains r if { is_object(input.role_assignment); r := input.role_assignment }`.
- **Verification:** Vector 32 in `test_azure_adversarial_integration.py`.

---

## 3. Policy & Test Suite Metrics

| Component | Pre-Hardening (G07.5) | Post-Hardening (G07.6) | Delta | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Platform Quality Checks** | 302 | **303** | +1 | 100% Passing |
| **Python Unit & Integration Tests** | 254 | **299** | +45 | 100% Passing |
| **OPA / Conftest Rego Tests** | 164 | **171** | +7 | 100% Passing |
| **Azure Adversarial Vectors** | 0 | **45** | +45 | 100% Passing |
| **Section 18 Checks** | 25 | **26** | +1 | 100% Passing |
| **Live Cloud Credentials** | 0 | **0** | 0 | Strict Zero |
| **Cloud Spend** | $0.00 | **$0.00** | $0.00 | Strict Zero |

### OPA Policy Breakdown (`conftest verify --policy policies/`)
- Common Policies: 47 tests
- AWS Policies: 35 tests
- GCP Policies: 42 tests
- Azure Policies: **47 tests**
  - `storage_network_test.rego`: 4 tests (legacy baseline)
  - `entra_oidc_test.rego`: **24 tests** (+6 tests)
  - `storage_backend_test.rego`: **19 tests** (+1 test)
- **Total: 171 passed, 0 failures, 0 skipped**

---

## 4. Adversarial Test Vector Matrix (45 Vectors)

The dedicated test suite `tests/test_azure_adversarial_integration.py` verifies 45 threat vectors across four functional domains:

### Category A: Identity, Entra ID, OIDC Trust Boundary & Input Guards (Vectors 1–21)
1. **Vector 1 (Positive Control):** Valid synthetic Azure configuration accepted cleanly.
2. **Vector 2:** Malformed Subscription ID (short, invalid hex character 'g', malformed hyphens, command injection) rejected.
3. **Vector 3:** Malformed Tenant ID rejected.
4. **Vector 4:** Malformed Client ID rejected.
5. **Vector 5:** Resource group naming violations (trailing period, >90 chars, forbidden characters, command injection) rejected.
6. **Vector 6:** Storage account naming violations (<3 or >24 chars, uppercase, dashes, underscores, injection) rejected.
7. **Vector 7:** Storage container naming violations (leading/trailing hyphen, consecutive hyphens `--`, uppercase, >63 chars) rejected.
8. **Vector 8:** State blob key traversal (leading slash, `..`, backslashes) rejected.
9. **Vector 9:** Cross-environment state collision defense (missing environment namespace) rejected.
10. **Vector 10:** Wildcard audience `*` in federated credential rejected.
11. **Vector 11:** Disallowed audience (non-`api://AzureADTokenExchange`) rejected.
12. **Vector 12:** Untrusted OIDC issuer (not `https://token.actions.githubusercontent.com`) rejected.
13. **Vector 13:** Wildcard subject `*` in federated credential rejected.
14. **Vector 14 (SEC-02):** Untrusted pull request event attempting credentials fail-closed in both Rego and workflow guard.
15. **Vector 15:** Malformed subject format rejected.
16. **Vector 16:** Missing parent identity binding (`parent_id` empty in `azurerm_federated_identity_credential`) rejected.
17. **Vector 17:** Repository identity substitution (`expected_repository` mismatch) rejected.
18. **Vector 18:** Repository ID substitution (`expected_repository_id` mismatch) rejected.
19. **Vector 19:** Flexible federated identity credential (custom `claims` block) rejected.
20. **Vector 20:** Overprivileged subscription-level Owner or Contributor role assignments rejected.
21. **Vector 21 (Positive Control):** Resource-group scoped least-privilege role assignment allowed.

### Category B: Azure Storage Account and Blob Backend Policies (Vectors 22–32)
22. **Vector 22:** Storage backend missing `use_azuread_auth = true` rejected.
23. **Vector 23:** Storage backend with `use_oidc = true` alone without `use_azuread_auth = true` rejected.
24. **Vector 24:** Storage backend specifying static `access_key` rejected.
25. **Vector 25:** Storage backend specifying static `sas_token` rejected.
26. **Vector 26:** Storage account setting `allow_nested_items_to_be_public = true` rejected.
27. **Vector 27:** Container setting `container_access_type != private` rejected.
28. **Vector 28:** Storage account with insecure TLS version (`TLS1_0`, `TLS1_1`) rejected.
29. **Vector 29:** Storage account with unrestricted public network access without Deny rule rejected.
30. **Vector 30:** Storage account enabling shared access keys (`shared_access_key_enabled = true`) rejected.
31. **Vector 31:** Storage account housing state missing blob versioning rejected.
32. **Vector 32:** Overprivileged Owner/Contributor role on storage account scope rejected.

### Category C: Reusable Workflow Pre-Flight Input Guards & Boundaries (Vectors 33–41)
33. **Vector 33:** Mutable reusable workflow reference (`@main` instead of 40-char SHA) rejected.
34. **Vector 34:** Attempted Azure authentication enablement (`enable-azure-auth: true`) fail-closed rejected.
35. **Vector 35:** Attempted bypass of mandatory policy evaluation (`enable-policy-evaluation: false`) rejected.
36. **Vector 36:** Attempted bypass of mandatory Trivy IaC scan (`enable-trivy: false`) rejected.
37. **Vector 37:** Unauthorized security severity threshold (`CRITICAL`, `LOW`, `MEDIUM`) rejected.
38. **Vector 38:** Reusable workflow rogue repository origin (`WORKFLOW_REPO != TM-threemavithana/infraflow`) rejected.
39. **Vector 39:** Mutable or non-40-hex `WORKFLOW_SHA` rejected.
40. **Vector 40:** Working directory path traversal (`..`, `/etc`, `~`) rejected.
41. **Vector 41:** Var-file path traversal (`..`, `/etc`, `~`) rejected.

### Category D: Execution, Plan Analysis, Cleanup and Aggregator Gates (Vectors 42–45)
42. **Vector 42:** Destructive changes gate evaluation (`has-destructive-changes: true`) verified in aggregation output.
43. **Vector 43:** Summary aggregator fail-closed when `validate-inputs` fails (`authorization-status=rejected`, exit 1).
44. **Vector 44:** Summary aggregator fail-closed on metric inconsistency (`has-changes: true, total-changes: 0`).
45. **Vector 45:** Plan cleanup trap ensures `plan-metrics.json` cleanup alongside `tfplan` and `tfplan.json`.

---

## 5. Security Invariant Checklist

| Invariant | Requirement | Status | Evidence |
| :--- | :--- | :--- | :--- |
| **INV-01** | Zero Cloud Spend ($0.00) | **MAINTAINED** | Fully offline simulation, 0 cloud API calls |
| **INV-02** | Zero Live Credentials | **MAINTAINED** | No Azure CLI login, mock providers only |
| **INV-03** | Fail-Closed on Auth Opt-In | **MAINTAINED** | `enable-azure-auth: true` terminates immediately |
| **INV-04** | SEC-02 PR Protection | **MAINTAINED** | Pull requests cannot trigger Azure auth |
| **INV-05** | Immutable 40-char SHA Pinning | **MAINTAINED** | Validated in workflow guard and policy tests |
| **INV-06** | Platform Isolation | **MAINTAINED** | Toolchain moved to `$RUNNER_TEMP`, symlinks rejected |
| **INV-07** | Cryptographic Plan Integrity | **MAINTAINED** | Plan JSON cleanup trap verified (zero state leaks) |
| **INV-08** | Entra ID Data Plane Mandate | **MAINTAINED** | `use_azuread_auth = true` strictly required |

---

## 6. Conclusion & Next Steps

Milestone G07.6 has successfully established a trustworthy, battle-tested security foundation for Microsoft Azure in InfraFlow. All known vulnerabilities have been corrected, 45 adversarial test vectors verify complete coverage, and 303 platform quality checks confirm zero regressions.

The Azure adapter is now certified ready for **Milestone G07.7 — External Azure Consumer Integration & Release Preparation**.
