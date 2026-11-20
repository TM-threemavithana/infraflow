# InfraFlow — Policy-as-Code Reference & Specification

## 1. Overview & Policy Hierarchy

InfraFlow uses **Open Policy Agent (OPA)** and **Conftest** to define, evaluate, and test infrastructure guardrails across multi-cloud environments. Policies are written in declarative **Rego (v1)** and structured hierarchically to allow general organizational guardrails to apply globally while cloud-specific controls apply per provider.

```
policies/
├── common/             # Global organizational rules applied to all modules
│   ├── tags.rego       # Mandatory tagging enforcement
│   └── naming.rego     # Canonical naming standards
├── aws/                # AWS Provider Policies
│   ├── s3.rego         # S3 encryption & public block
│   └── network.rego    # Security group ingress restrictions
├── azure/              # Azure Provider Policies
│   └── storage.rego    # Blob storage public access & TLS restrictions
└── gcp/                # Google Cloud Provider Policies
    └── storage.rego    # GCS uniform bucket-level access
```

---

## 2. Policy Input Contracts

InfraFlow policies evaluate infrastructure at two distinct lifecycle checkpoints:

### 2.1 Static HCL Input Contract (`--parser hcl2`)
When evaluating source `.tf` files directly:
```json
{
  "resource": {
    "<resource_type>": {
      "<resource_name>": [
        {
          "<attribute_key>": "<attribute_value>"
        }
      ]
    }
  }
}
```

### 2.2 Terraform Plan JSON Contract (`terraform show -json`)
When evaluating speculative execution plans:
```json
{
  "format_version": "1.2",
  "resource_changes": [
    {
      "address": "aws_s3_bucket.data",
      "type": "aws_s3_bucket",
      "name": "data",
      "change": {
        "actions": ["create"],
        "after": {
          "bucket": "enterprise-data-store",
          "tags": { ... }
        }
      }
    }
  ]
}
```

> [!WARNING]
> **Synthetic Plan Enforcement Boundary**:
> Plan evaluation verifies that the planned actions within Terraform HCL adhere to defined policy rules. It validates code and planned state *prior* to cloud application. **Synthetic plan evaluation does not prove runtime cloud enforcement** (e.g. out-of-band cloud console modifications, AWS SCPs, Azure Policy engines, or GCP Organization Policies).

---

## 3. Implemented Policies (Milestone G03 Scope)

The following policies are fully implemented, accompanied by unit tests (`_test.rego`), and verified in G03:

### 3.1 Common Policies (`policies/common/`)

#### 1. Mandatory Tagging & Labeling (`tags.rego`)
- **Package**: `main`
- **Rule**: `deny`
- **Specification (G03.2 Hardened)**: Replaces blanket prefix matching with **explicit cloud resource allowlists** and distinct metadata mapping across clouds:
  - **AWS (`aws_taggable_resources`)**: Enforces `tags` block (`aws_s3_bucket`, `aws_instance`, `aws_vpc`, `aws_security_group`, `aws_subnet`, `aws_route_table`, `aws_ebs_volume`, `aws_kms_key`, etc.).
  - **Azure (`azure_taggable_resources`)**: Enforces `tags` block (`azurerm_storage_account`, `azurerm_resource_group`, `azurerm_virtual_network`, `azurerm_network_security_group`, `azurerm_linux_virtual_machine`, etc.).
  - **GCP (`gcp_labelable_resources`)**: Enforces `labels` block (`google_storage_bucket`, `google_compute_instance`, `google_bigquery_dataset`, `google_container_cluster`, etc.).
- **Zero False-Positive Invariant**: Resources that legitimately do NOT support metadata tags (such as `aws_route_table_association`, `aws_s3_bucket_public_access_block`, `azurerm_subnet_network_security_group_association`, `google_compute_network`, `google_compute_firewall`, `terraform_data`) are excluded from allowlists and produce zero false positives when defined without tags.
- **Enforcement Rules**:
  1. Allowlisted AWS/Azure resources must define a `tags` block; allowlisted GCP resources must define a `labels` block.
  2. Required attributes: `Environment` (or `environment`), `ManagedBy` (or `managed_by`), `Project` (or `project`).
  3. Allowed Environments: `dev`, `staging`, `prod`, `test` (case-insensitive).
- **Violation Messages**:
  - `Resource '<name>' is missing mandatory 'tags' block`
  - `Resource '<name>' is missing mandatory 'labels' block`
  - `Resource '<name>' is missing mandatory tag/label '<key>'`
  - `Resource '<name>' has invalid Environment '<val>'. Allowed: [...]`

#### 2. Naming Standards (`naming.rego`)
- **Package**: `main`
- **Rule**: `deny`
- **Enforcement**: Resource names must follow lowercase alphanumeric hyphenated format (`^[a-z0-9-]+$`).

#### 3. Plan JSON Evaluation & Security Control Lifecycle Governance (`plan.rego`)
- **Package**: `main`
- **Rule**: `deny`
- **Specification (G03.2.1 Hardened)**: Evaluates speculative Terraform execution plans across all lifecycle actions (`create`, `update`, `delete`, and both replacement orderings `["delete", "create"]` and `["create", "delete"]`):
  1. **Strict Parent-Child Deletion Correlation**: Standalone security controls (`aws_s3_bucket_public_access_block`, `aws_s3_bucket_server_side_encryption_configuration`, `azurerm_storage_account_network_rules`, `aws_s3_bucket_policy`) are strictly blocked from deletion while their protected parent asset remains active. Deletion is permitted ONLY when the exact target parent resource is also being decommissioned in the exact same plan.
     - **Module Instance Scope**: Both security control and parent asset must share identical module scope (`same_module_scope`). A parent destroyed in a different module instance cannot authorize deleting a security control in another module.
     - **Exact Resource Identity**: Parent correlation requires exact matching against target attributes (`before.bucket`, `before.id`, `before.arn` for S3; `before.storage_account_name` or `before.storage_account_id` for Azure). Broad resource-type existence does NOT prove parent decommissioning.
  2. **Safe Deletion Allowance**: Deletion of ordinary non-security infrastructure (`aws_instance`, `terraform_data`, `aws_ebs_volume`) is permitted without blocking.
  3. **Replacement Actions**: Both replacement action orderings (`["delete", "create"]` and `["create", "delete"]`) are evaluated against the proposed `after` configuration. Any replacement that strips security protections is blocked regardless of action sequence.
  4. **Unknown Security Attributes (`after_unknown`)**: Enforces the fail-closed principle. Plans with speculative/unknown values on security-critical attributes (`acl`, `block_public_acls`, `min_tls_version`, `uniform_bucket_level_access`) are blocked, requiring explicit static declarations.
  5. **Incomplete or Errored Plan Detection**: Fails closed if the plan indicates errors (`errored: true`), is missing `resource_changes`, contains null `change` blocks, or is missing `change.actions`.
  6. **Module Address Containment**: Recursively evaluates resource addresses across all hierarchy depths (`module.<name>.<resource_type>.<name>`).

---

## 4. Policy Decision Matrix for Terraform Plan Operations

| Operation Type | Target Resource Type | Before / After State | Policy Decision | Technical Rationale |
|---|---|---|---|---|
| **Pure Deletion (`["delete"]`)** | Security Control (`aws_s3_bucket_public_access_block`, `aws_s3_bucket_server_side_encryption_configuration`, `azurerm_storage_account_network_rules`, `aws_s3_bucket_policy`) | `before: { ... }`<br>`after: null`<br>(Parent asset active) | **BLOCKED (Exit 1)** | Stripping standalone security controls exposes active infrastructure to public networks or removes encryption at rest without an audit trail. |
| **Pure Deletion (`["delete"]`)** | Security Control | `before: { ... }`<br>`after: null`<br>(Exact parent deleted in same module scope) | **ALLOWED (Exit 0)** | Safe decommissioning of entire asset stack (parent asset is destroyed simultaneously within the same module scope). |
| **Pure Deletion (`["delete"]`)** | Security Control | `before: { ... }`<br>`after: null`<br>(Different bucket/account destroyed) | **BLOCKED (Exit 1)** | Destroying an unrelated bucket does not authorize stripping protections from another active bucket. |
| **Pure Deletion (`["delete"]`)** | Security Control | `before: { ... }`<br>`after: null`<br>(Parent destroyed in different module instance) | **BLOCKED (Exit 1)** | Cross-module instance boundaries are enforced; parent deletion in `module.b` cannot satisfy control deletion in `module.a`. |
| **Pure Deletion (`["delete"]`)** | Ordinary Infrastructure (`aws_instance`, `terraform_data`, `aws_ebs_volume`) | `before: { ... }`<br>`after: null` | **ALLOWED (Exit 0)** | Deleting ordinary compute, test, or data assets removes resources without weakening surrounding security controls. |
| **Replacement (`["delete", "create"]`)** | Security Control / Protected Resource | `before: { ... }`<br>`after: { insecure }` | **BLOCKED (Exit 1)** | Recreating a resource with degraded security settings via delete/create is rejected. |
| **Replacement (`["create", "delete"]`)** | Security Control / Protected Resource | `before: { ... }`<br>`after: { insecure }` | **BLOCKED (Exit 1)** | Recreating a resource with degraded security settings via create/delete is rejected. |
| **Replacement (`["delete", "create"]`)** | Security Control / Protected Resource | `before: { ... }`<br>`after: { secure }` | **ALLOWED (Exit 0)** | Recreating a resource while maintaining compliant security settings via delete/create is valid. |
| **Replacement (`["create", "delete"]`)** | Security Control / Protected Resource | `before: { ... }`<br>`after: { secure }` | **ALLOWED (Exit 0)** | Recreating a resource while maintaining compliant security settings via create/delete is valid. |
| **Speculative Unknown (`after_unknown`)** | Security-Critical Attribute (`acl`, `block_public_acls`, `min_tls_version`, `uniform_bucket_level_access`) | `after_unknown: { attr: true }`<br>`after: { attr absent }` | **BLOCKED (Exit 1)** | Fail closed: Computed security attributes cannot be verified statically and must be explicitly declared in source HCL. |
| **Speculative Unknown (`after_unknown`)** | Ordinary Attribute (e.g. `ami`, `private_ip`, `id`) | `after_unknown: { ip: true }` | **ALLOWED (Exit 0)** | Normal dynamic runtime attributes are permitted to compute dynamically. |
| **Plan Malformation** | Plan Input (`errored: true` or missing `resource_changes`) | Corrupted plan JSON | **BLOCKED (Exit 1)** | Fail closed: Execution plans reflecting generation errors or missing data cannot guarantee compliance. |

---

## 5. Policy Unit Testing Suite (62/62 Tests)

All policies are verified by 62 native Rego unit tests executed via `conftest verify --policy policies`:

| Test Suite File | Tests | Validated Scenarios |
|---|---|---|
| `policies/common/tags_test.rego` | 18 | AWS/Azure/GCP missing tags/labels, missing Environment/ManagedBy/Project, invalid environment values, valid metadata passes, unsupported resources without tags allowed (zero false positives) |
| `policies/common/naming_test.rego` | 2 | `invalid_resource_name`, `valid_resource_name` |
| `policies/common/plan_test.rego` | 27 | Plan public S3 denied, nested module S3 denied, unknown ACL/PAB/TLS/uniform access denied, standalone security control deletion denied when parent active, deletion allowed when exact parent deleted, deletion denied when different bucket deleted, deletion denied when different module parent deleted, Azure network rules parent correlation tests (same module, different storage, different module), safe deletion of ordinary resource, insecure replacement denied (delete/create & create/delete), secure replacement allowed (delete/create & create/delete), errored plan denied, missing resource changes denied, null change block denied, valid S3/Azure/GCP plans allowed |
| `policies/aws/s3_test.rego` | 5 | `s3_public_acl_denied`, `s3_private_acl_allowed`, `s3_pab_denied_when_false`, `s3_pab_denied_when_omitted`, `s3_pab_allowed_when_all_true` |
| `policies/aws/network_test.rego` | 3 | `unrestricted_ssh_denied`, `restricted_ssh_allowed`, `unrestricted_http_allowed` |
| `policies/azure/storage_test.rego` | 4 | `storage_public_access_denied`, `storage_insecure_tls_denied`, `storage_omitted_tls_denied`, `storage_secure_allowed` |
| `policies/gcp/storage_test.rego` | 3 | `gcs_uniform_access_denied_when_false`, `gcs_uniform_access_denied_when_omitted`, `gcs_uniform_access_allowed_when_true` |
| **Total** | **62** | **62 Passed, 0 Failures, 0 Warnings, 0 Exceptions, 0 Skipped** |

---

## 6. Known Limitations & Architectural Boundaries

1. **Cross-State Reference Scope**: Terraform plan JSON only contains resources modified or evaluated within the current root execution. In multi-state or multi-repository architectures where a bucket was created in repo A and public access block was created in repo B, deleting repo B's resource cannot correlate state with repo A's bucket plan. Such standalone security deletions will fail closed, requiring an authorized security exception or central governance.
2. **Actionlint vs Zizmor Parser Boundary**: `actionlint` v1.7.7 strictly rejects Zizmor's recommended `$/...` repository-relative workflow format. The narrow rule exception `rules.self-repository.ignore: ["ci.yml"]` in `.zizmor.yml` remains mandatory until Actionlint implements `$/...` support.
3. **TFLint Offline Plugin Limitation**: Cloud provider plugins (`tflint-ruleset-aws`, etc.) require network installation via `tflint --init`. For 100% offline and $0 budget compliance, external plugins are commented out; deep misconfiguration scanning is performed offline by Aqua Trivy and Conftest/OPA.

---

## 4. Future Policy Roadmap (Milestone G04+)

The following advanced policy domains are scheduled for subsequent program milestones:
- **IAM Least Privilege**: Detection of wildcard permissions (`"Action": "*"`, `"Resource": "*"`) in IAM policy documents.
- **VPC Flow Logging**: Enforcing mandatory flow logs on AWS VPCs, Azure VNets, and GCP VPC networks.
- **Database Encryption & Multi-AZ**: Requiring KMS encryption and high-availability configuration for RDS, Cloud SQL, and Azure SQL instances.
- **KMS Key Rotation**: Enforcing automated 90/365-day annual key rotation for customer-managed KMS keys.
- **Drift Detection Policies**: Scanning actual cloud infrastructure against state to detect out-of-band drifts (G04).
