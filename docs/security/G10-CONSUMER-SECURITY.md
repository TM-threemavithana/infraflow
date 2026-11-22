# InfraFlow Consumer Security Architecture: Secret Defense & Semantic Destruction Protection (G10.3)

## 1. Executive Summary

Milestone **G10.3** introduces deep security defense mechanisms into the InfraFlow platform to protect enterprise consumers from the two highest-consequence failure modes in multi-tenant infrastructure operations:
1. **Unintentional Secret & Credential Leakage:** Hardcoded cloud access tokens, SSH/TLS private keys, and API tokens committed into consumer infrastructure code.
2. **Catastrophic Infrastructure Destruction:** Semantic destruction or recreation of persistent databases, encryption keys (KMS/Vault), identity perimeters, or storage containers caused by innocuous Terraform code refactoring or attribute changes.

These defenses operate under a **zero-trust, fail-closed architecture** that cannot be bypassed, suppressed, or disabled by consumer configuration.

---

## 2. Threat Modeling & STRIDE Matrix

| Threat Category | STRIDE Vector | Attack / Failure Scenario | InfraFlow G10.3 Mitigation |
|---|---|---|---|
| **Credential Infiltration** | Information Disclosure | Developer accidentally commits AWS access key or GitHub PAT in `.tf` files or local variables. | Mandatory consumer-side secret scanning (`SecretScanner`) scans codebase before any plan generation; fails closed with exit code 1. |
| **Token Log Leakage** | Information Disclosure | Secret scanner prints raw detected tokens in CI/CD step logs or summaries. | `SecretSanitizer` redacts raw secret tokens in all logs, console outputs, and JSON reports; only exposes rule name and non-sensitive token prefix. |
| **Scanner Bypass** | Elevation of Privilege | Consumer sets `enforce_mandatory_scanners: false` in `infraflow.config.yaml` to circumvent checks. | `validate-consumer.py` strictly validates schema and policy; central governance workflow overrides and ignores consumer bypass attempts. |
| **Silent Resource Deletion** | Tampering / Denial of Service | Malicious or accidental PR deletes primary production database (`aws_db_instance`, `azurerm_postgresql_server`, `google_sql_database_instance`). | OPA/Conftest `critical_resources.rego` and `assess-destruction.py` intercept deletion actions and deny execution unconditionally unless authorized. |
| **Silent Key Destruction (Recreate)** | Denial of Service / Repudiation | Refactoring KMS key name or encryption configuration forces resource replacement (`["delete", "create"]` or `["create", "delete"]`), rendering all encrypted data irrecoverable. | Semantic policy evaluates all multi-step action lists; detects both destroy-before-create and create-before-destroy replacements and blocks them. |
| **Generic Token Forgery** | Spoofing / Elevation of Privilege | Attacker or developer passes generic confirmation tokens (`confirm`, `true`, `yes`, `approved`, `force`) in plan metadata or PR comments. | Semantic policy strictly rejects trivial tokens; requires cryptographically signed authorization payloads (`infraflow-destruction-confirmation-v1`) bound to the exact plan SHA-256 digest. |
| **Malformed Plan Evasion** | Defense Evasion | Attacker crafts ambiguous or corrupt `actions` field (`["destroy"]`, `["unknown"]`, null) hoping parser defaults to allow. | Fail-closed policy evaluates unrecognized actions and flags them as validation errors. |

---

## 3. Pillar 1: Consumer Secret Defense (`SecretScanner`)

### 3.1 Scanner Architecture & Detection Rules

The secret detection engine is implemented in `infraflow/scanner.py` and exposed via `scripts/scan-secrets.py`. It inspects consumer repositories before any Terraform commands are executed.

```
+-------------------------------------------------------------------------------+
|                         Consumer Repository Changes                           |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                       File Filtering & Exclusions                            |
|  - Skips VCS directories (.git, .terraform)                                  |
|  - Skips Binary Plan Files (tfplan, *.tfplan.binary, *.enc.json)              |
|  - Respects Maximum File Size Limits (10 MB)                                  |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                         Regex Rule Matching Engine                            |
|  - AWS Access Keys (AKIA..., ASIA...)                                         |
|  - AWS Secret Access Keys (40-char base64)                                    |
|  - GitHub Tokens (ghp_..., github_pat_..., gho_..., ghu_..., ghs_..., ghr_...) |
|  - PEM Private Keys (RSA, EC, OPENSSH, DSA, PGP)                              |
|  - High-Entropy Passwords & Passphrases                                      |
|  - Google Cloud API Keys (AIza...)                                            |
|  - Slack API & Webhook Tokens (xoxb-..., xoxp-...)                            |
|  - Authorization Bearer & Basic Tokens                                        |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                    Placeholder & Template Filtering                          |
|  - Terraform variables: ${var.db_password}, var.secret_token                 |
|  - Template place-holders: changeme, placeholder, dummy_token, <redacted>     |
|  - Excludes safe reference patterns while preserving real credentials        |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
|                      Redaction & Zero-Leakage Reporting                       |
|  - Masking: First 4 chars + '***' + Last 2 chars                             |
|  - Fail-Closed: Non-zero exit code if any secret is confirmed                 |
+-------------------------------------------------------------------------------+
```

### 3.2 Supported Secret Signatures

| Rule ID | Name | Pattern Description |
|---|---|---|
| `SEC-001` | AWS Access Key ID | Standard (`AKIA[0-9A-Z]{16}`) and temporary (`ASIA[0-9A-Z]{16}`) credentials. |
| `SEC-002` | AWS Secret Access Key | 40-character base64-encoded secret keys assigned alongside AWS Key IDs. |
| `SEC-003` | GitHub Personal Access Token | Classic tokens (`ghp_[A-Za-z0-9]{36}`) and fine-grained PATs (`github_pat_[A-Za-z0-9_]{82}`). |
| `SEC-004` | GitHub OAuth & App Token | App, refresh, and user tokens (`gho_`, `ghu_`, `ghs_`, `ghr_`). |
| `SEC-005` | Cryptographic Private Key | PEM headers for RSA, DSA, EC, OPENSSH, and PGP private keys (`-----BEGIN ... PRIVATE KEY-----`). |
| `SEC-006` | Generic Password Assignment | Hardcoded passwords in variable assignments (`password = "..."`). |
| `SEC-007` | Google Cloud API Key | Standard Google API keys (`AIza[0-9A-Za-z\\-_]{35}`). |
| `SEC-008` | Slack API Token | Bot and user workspace tokens (`xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}`). |
| `SEC-009` | Bearer Authorization Token | Hardcoded HTTP Bearer header assignments (`Bearer ey...`). |

### 3.3 Zero Raw Secret Exposure Invariant

A fundamental security principle of InfraFlow is that **detection must never become disclosure**.
- Scanner logs and summaries mask the middle portion of all sensitive matches:
  ```text
  [CRITICAL] Hardcoded secret detected in terraform/database.tf:14
  Rule: SEC-001 (AWS Access Key ID)
  Masked Value: AKIA********************
  ```
- Binary files, such as encrypted plan envelopes (`*.enc.json`) or binary plan artifacts (`tfplan`), are skipped by default to eliminate false-positive detection of encrypted ciphertext.

---

## 4. Pillar 2: Semantic Destruction Protection (`critical_resources.rego`)

### 4.1 Why Deletion-Count Thresholds Are Insufficient

Prior to G10.3, infrastructure pipelines typically relied on *quantitative deletion limits* (e.g., `max_allowed_deletions: 5`). While deletion counts catch massive wholesale teardowns, they fail to protect against targeted, catastrophic single-resource destructions:
1. **Single-Asset Wipeout:** Dropping a single multi-terabyte production database (`aws_db_instance`) counts as `1` deletion, passing a `max_allowed_deletions: 5` threshold.
2. **Replacement-Induced Erasure:** Renaming or updating an immutable property of an encryption key causes Terraform to plan a `["delete", "create"]` replacement. This is conceptually a recreation, but functionally results in the total destruction of the existing cryptographic key and permanent loss of encrypted data.

InfraFlow G10.3 replaces crude counting with **semantic resource classification and action sequence analysis**.

### 4.2 Multi-Cloud Critical Resource Catalog

The policy defines a rigorous catalog of critical resource types across AWS, Azure, and Google Cloud:

```rego
critical_resource_types := {
    # Relational & NoSQL Databases
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_dynamodb_table",
    "azurerm_mssql_database",
    "azurerm_mssql_server",
    "azurerm_postgresql_server",
    "azurerm_cosmosdb_account",
    "google_sql_database_instance",
    "google_spanner_instance",
    "google_spanner_database",
    "google_bigtable_instance",

    # Cryptographic Key Vaults & Master Keys
    "aws_kms_key",
    "azurerm_key_vault",
    "azurerm_key_vault_key",
    "google_kms_crypto_key",
    "google_kms_key_ring",

    # Object Storage Accounts & Buckets
    "aws_s3_bucket",
    "azurerm_storage_account",
    "google_storage_bucket",

    # Identity & Access Governance
    "aws_iam_role",
    "aws_iam_policy",
    "azurerm_role_definition",
    "azurerm_role_assignment",
    "google_project_iam_binding",
    "google_project_iam_member",

    # Network Security Perimeters
    "aws_security_group",
    "azurerm_network_security_group",
    "google_compute_firewall"
}
```

### 4.3 Action Differentiation & Replacement Safety

Terraform plan JSON represents changes in the `resource_changes[].change.actions` array. The semantic policy distinguishes three critical lifecycle behaviors:

1. **Direct Deletions (`actions: ["delete"]`):**
   The resource is being explicitly removed from infrastructure state. Strictly blocked unless authenticated via a cryptographic confirmation token.
2. **Destroy-Before-Create Replacements (`actions: ["delete", "create"]`):**
   Terraform must destroy the existing resource before provisioning its successor. For databases or KMS keys, this results in data loss or service downtime. Strictly blocked.
3. **Create-Before-Destroy Replacements (`actions: ["create", "delete"]`):**
   Terraform creates the new resource first, then deletes the original. While less dangerous than destroy-before-create, for unique singletons (like storage account names or key rings), this may fail or lead to split-brain states. Evaluated as a deletion action and gated by policy.
4. **Malformed / Ambiguous Actions:**
   Any unrecognized actions array is treated as untrusted and rejected fail-closed.

### 4.4 Cryptographic Confirmation vs Generic Tokens

Generic confirmation tokens are strictly prohibited:
```rego
generic_tokens := {"yes", "true", "confirm", "confirmed", "force", "approved", "allow", "ok", "1"}
```
If a plan contains an `infraflow_authorization` object with a generic token, the policy denies execution with:
```text
Generic confirmation token 'confirm' is rejected. Semantic destruction requires a cryptographically signed plan confirmation token.
```
To authorize destruction:
1. The change must be formally approved in the designated production environment.
2. An authorization payload matching schema `infraflow-destruction-confirmation-v1` must be provided, binding the approval to the specific plan SHA-256 digest and environment name.

### 4.5 Parent-Child Decommissioning Lifecycle

To prevent false-positive blocks when an entire environment is intentionally decommissioned, the policy features a paired decommissioning detector (`is_decommissioning`):
- If a child resource (like an S3 bucket policy or storage network rule) is deleted alongside its parent resource in the same plan, the policy recognizes the coordinated lifecycle and permits the decommission without requiring separate redundant overrides.

---

## 5. Central Governance Integration

The secret scanning and semantic destruction gates are embedded in `.github/workflows/reusable-tf-governance.yml`:

```yaml
- name: Execute Mandatory Consumer Secret Scanner
  id: secret_scanner
  shell: bash
  env:
    CONSUMER_DIR: ${{ inputs.terraform-directory }}
  run: |
    python3 "${PLATFORM_REPO_DIR}/scripts/scan-secrets.py" \
      --target-dir "${CONSUMER_DIR}" \
      --strict \
      --json > secret-scan-summary.json
```

### 5.1 Non-Bypassable Contract

- Consumers define an `infraflow.config.yaml` file in their repository.
- If a consumer repository specifies `security_controls.enforce_mandatory_scanners: false`, `validate-consumer.py` rejects the configuration during pre-flight validation.
- Even if a consumer configures custom flags, the central platform reusable workflow enforces the secret scanner unconditionally before invoking any cloud adapters.

---

## 6. Developer Remediation Guides

### 6.1 Resolving a Secret Scanner Violation

**Symptom:** CI fails with `[CRITICAL] Hardcoded secret detected in terraform/main.tf:22`.

**Remediation Steps:**
1. **Never commit raw credentials to Git.**
2. Remove the hardcoded secret from the file.
3. If the credential was committed to Git history, rotate the credential immediately in the cloud provider console.
4. Store the sensitive credential in GitHub Secrets, AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault.
5. In Terraform, reference the secret using a sensitive input variable:
   ```hcl
   variable "db_password" {
     type      = string
     sensitive = true
   }
   ```
6. Run `infraflow validate` locally to confirm the scanner passes before pushing.

### 6.2 Resolving a Semantic Destruction Rejection

**Symptom:** CI fails with `Direct deletion of critical resource 'aws_db_instance.primary' is blocked by InfraFlow semantic destruction policy.`

**Remediation Steps:**
1. **Investigate Intent:** Determine why the database is marked for deletion.
   - Did a resource rename cause Terraform to treat it as a delete/create? Use `moved` blocks to preserve state:
     ```hcl
     moved {
       from = aws_db_instance.old_name
       to   = aws_db_instance.new_name
     }
     ```
   - Did an immutable attribute change force replacement? Review the plan to find which argument has `~ attribute (forces replacement)`.
2. **Intentional Decommissioning:**
   - If the resource deletion is genuinely intended, submit an authorized Decommission Request via the platform operations portal.
   - Generate an authorized cryptographic destruction token signed for the specific plan digest.
   - Provide the signed token in the governance workflow dispatch inputs.

---

## 7. Security Integration Assurance & Decommission Hardening (G10.3.1)

### 7.1 Decommission Substring Bypass Audit & Resolution

During independent security integration assurance (G10.3.1), an audit of `policies/common/critical_resources.rego` identified a heuristic flaw in the legacy decommission logic:
- **Flaw:** The rule previously considered a resource to be in "decommissioning" state if its address or name contained the substring `"decommission"` or `"decomm"`.
- **Attack Vector:** An engineer or adversary could rename an unauthorized critical resource deletion to include `"decommission"` (e.g. `aws_s3_bucket.decommissioned_prod_data`), bypassing deletion protections without cryptographic authorization.
- **Remediation:** The heuristic substring check was completely removed. Decommissioning now strictly and exclusively requires platform-controlled, cryptographically signed plan confirmation (`is_plan_authorized` verifying `infraflow-destruction-confirmation-v1`). Unauthorized decommissioning plans are fail-closed.

### 7.2 Multi-Workflow Secret Scanning Architecture

Secret defense has been expanded from a single governance workflow to run unconditionally across all six reusable delivery workflows:
1. `reusable-tf-plan.yml` (Pre-plan scan before speculative execution)
2. `reusable-tf-aws.yml` (Pre-execution adapter gate)
3. `reusable-tf-azure.yml` (Pre-execution adapter gate)
4. `reusable-tf-gcp.yml` (Pre-execution adapter gate)
5. `reusable-tf-security.yml` (Standalone security verification)
6. `reusable-tf-governance.yml` (Central policy orchestration)

All workflows emit a standardized step output: `secret-scan-status` (`success` or `failure`).

### 7.3 Multi-Cloud Conftest Namespace Evaluation

In Azure (`reusable-tf-azure.yml`) and GCP (`reusable-tf-gcp.yml`), Conftest was previously invoked without `--all-namespaces`, which defaulted evaluation to `package main` and silently bypassed `package common.critical_resources`.
- **Resolution:** Added `--all-namespaces` to both workflows, guaranteeing that all 213 OPA policies across common, cloud-specific, and governance namespaces are evaluated against Terraform plan JSON before any workflow authorization.

### 7.4 Defensive Input Guard Hardening

To ensure that callers cannot bypass security scanning via caller workflow inputs:
- `reusable-tf-plan.yml` enforces fail-closed rejection of `enable-policy-evaluation: false` and `enable-trivy: false`.
- `reusable-tf-security.yml` enforces fail-closed rejection of `enable-trivy: false` and `enable-conftest: false`.
- Combined with `reusable-tf-aws.yml`, `azure.yml`, and `gcp.yml`, zero execution paths permit disabling mandatory security scanners.
