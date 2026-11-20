# InfraFlow — Cloud Adapters Specification (Future AWS, Azure, GCP)

## 1. Adapter Architecture Overview

InfraFlow strictly isolates provider-neutral CI/CD logic from cloud-specific deployment operations. 

While **Milestone G02** establishes the provider-neutral core (`reusable-tf-validate.yml`), this document specifies the technical design, security contracts, and implementation blueprints for future cloud adapters (**Milestone G03**).

```mermaid
flowchart TD
    subgraph CoreEngine["InfraFlow Core Engine (G02)"]
        ValidateCore["reusable-tf-validate.yml\n- Syntax Check\n- Static Validate\n- Native Unit Tests\n(Zero Cloud Credentials)"]
    end

    subgraph BranchCheck{"Git Ref Evaluation"}
        BranchCheck -->|"PR Event"| EndPR["Stop: Status Reported to PR\nNo Cloud Access"]
        BranchCheck -->|"Merged to Main"| RouteAdapter["Route to Target Cloud Adapter"]
    end

    subgraph Adapters["Cloud Adapters (G03 Future Scope)"]
        AWSAdapt["AWS Adapter\n(reusable-tf-aws.yml)"]
        AzureAdapt["Azure Adapter\n(reusable-tf-azure.yml)"]
        GCPAdapt["GCP Adapter\n(reusable-tf-gcp.yml)"]
    end

    ValidateCore --> BranchCheck
    RouteAdapter --> AWSAdapt
    RouteAdapter --> AzureAdapt
    RouteAdapter --> GCPAdapt
```

---

## 2. Universal Adapter Contract

Every cloud adapter must conform to the following architectural standard:

1. **Passwordless OIDC Authentication**:
   - Zero static long-lived credentials (no AWS Access Keys, no Azure Service Principal client secrets, no GCP service account JSON keys).
   - Authentication must use short-lived OIDC tokens minted by GitHub's token authority (`token.actions.githubusercontent.com`).
2. **Explicit Token Elevation Scoping**:
   - `permissions: id-token: write` is granted **only** in the adapter job executing on a protected branch.
3. **Decoupled State Backend Initialization**:
   - Cloud adapters dynamically inject backend configuration (`terraform init -backend-config=...`) rather than hardcoding backend credentials in source code.
4. **Plan-Before-Apply Safety**:
   - Planning writes a cryptographic plan file (`tfplan`). Applies must only execute against the approved plan file artifact.

---

## 3. Provider Specifications

### 3.1 AWS Adapter Specification (`reusable-tf-aws.yml`)

#### Authentication Flow
- **Mechanism**: AWS IAM OpenID Connect (OIDC) Identity Provider.
- **Action**: `aws-actions/configure-aws-credentials` (SHA pinned).
- **Trust Policy Condition**:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
        },
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
          "StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
          },
          "StringLike": {
            "token.actions.githubusercontent.com:sub": "repo:<ORG>/<REPO>:ref:refs/heads/main"
          }
        }
      }
    ]
  }
  ```

#### State Management
- **Backend Type**: `s3`
- **Bucket Configuration**: Amazon S3 with SSE-KMS encryption, versioning enabled, public access blocked.
- **Locking**: Amazon DynamoDB table with `LockID` string partition key.

---

### 3.2 Azure Adapter Specification (`reusable-tf-azure.yml`)

#### Authentication Flow
- **Mechanism**: Microsoft Entra ID Workload Identity Federation.
- **Action**: `azure/login` (SHA pinned).
- **Federated Credential**:
  - **Issuer**: `https://token.actions.githubusercontent.com`
  - **Subject**: `repo:<ORG>/<REPO>:ref:refs/heads/main`
  - **Audience**: `api://AzureADTokenExchange`

#### State Management
- **Backend Type**: `azurerm`
- **Storage**: Azure Storage Account Blob Container with immutable blob versioning.
- **Locking**: Native Azure Blob Lease locking mechanism.

---

### 3.3 GCP Adapter Specification (`reusable-tf-gcp.yml`)

#### Authentication Flow & Trust Model
- **Mechanism**: Google Cloud Workload Identity Federation (WIF) via GitHub Actions OIDC.
- **Action**: `google-github-actions/auth` (immutable commit SHA pinned).
- **WIF Configuration & Security Invariants**:
  - **Pool & Provider**: `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL>/providers/<PROVIDER>`
  - **Audience Validation**: Must strictly match the canonical provider resource URI. Wildcard (`*`) audiences are strictly rejected.
  - **Attribute Mapping**:
    - `google.subject = assertion.sub`
    - `attribute.repository = assertion.repository`
    - `attribute.ref = assertion.ref`
    - `attribute.actor = assertion.actor`
  - **Attribute Condition**: Mandatory CEL restriction enforcing repository and branch isolation:
    `assertion.repository == 'TM-threemavithana/infraflow' && assertion.ref == 'refs/heads/main'`
  - **Service Account Binding**: Role `roles/iam.workloadIdentityUser` assigned exclusively via `principalSet`:
    `principalSet://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL>/attribute.repository/<OWNER>/<REPO>`
    Wildcard principals (`allUsers`, `allAuthenticatedUsers`, `*`) and unbounded org-level bindings are strictly prohibited.
- **Fail-Closed Simulation Invariant**:
  - In Milestone G07.2, live GCP authentication is strictly disabled (`enable-gcp-auth: false`). Setting `enable-gcp-auth: true` triggers an immediate fail-closed security error.
  - Untrusted pull requests (`pull_request`, `pull_request_target`) are strictly prohibited from enabling live authentication (SEC-02).

#### State Management & GCS Backend Contract
- **Backend Type**: `gcs`
- **Bucket Security Controls**:
  - **Uniform Bucket-Level Access (UBLA)**: Explicitly enforced (`uniform_bucket_level_access = true`, CIS GCP 5.2).
  - **Public Access Prevention**: Explicitly set to `enforced` (CIS GCP 5.1).
  - **Object Versioning**: Explicitly enabled (`versioning.enabled = true`) for state resilience and recovery.
  - **Accidental Destruction**: `force_destroy = false` enforced.
  - **Encryption**: Customer-Managed Encryption Keys (CMEK) via Cloud KMS supported and validated.
  - **Zero Public Access**: Rejection of public ACLs (`google_storage_bucket_acl`) and public IAM members (`allUsers`, `allAuthenticatedUsers`).
- **State Locking**: Native GCS generation match precondition locking (`if-generation-match`).

#### Reference Implementation & Testing
- **Module Location**: `examples/gcp-reference-module/`
- **Mock Provider Testing**: Uses native Terraform `>= 1.7.0` provider mocking (`mock_provider "google" {}`) in `tests/gcs_test.tftest.hcl` for deterministic offline verification without cloud spend ($0.00).

---

## 4. Adapter Interface Schema (Future G03)

```yaml
inputs:
  cloud-provider:
    description: 'Target cloud adapter: aws | azure | gcp'
    required: true
    type: string
  environment:
    description: 'Deployment target environment: dev | staging | prod'
    required: true
    type: string
  oidc-role:
    description: 'Cloud IAM Role / Workload Identity identifier'
    required: true
    type: string
  backend-config:
    description: 'Path or inline key-values for backend-config'
    required: true
    type: string
  action:
    description: 'Execution action: plan | apply'
    required: false
    default: 'plan'
    type: string
```
