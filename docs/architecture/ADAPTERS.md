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

#### Authentication Flow
- **Mechanism**: Google Cloud Workload Identity Federation (WIF).
- **Action**: `google-github-actions/auth` (SHA pinned).
- **WIF Configuration**:
  - **Pool & Provider**: `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL>/providers/<PROVIDER>`
  - **Attribute Mapping**: `google.subject=assertion.sub`, `attribute.repository=assertion.repository`
  - **Service Account Binding**: Role `roles/iam.workloadIdentityUser` assigned to member `principalSet://iam.googleapis.com/...`

#### State Management
- **Backend Type**: `gcs`
- **Storage**: Google Cloud Storage Bucket with Uniform Bucket-Level Access and object versioning.
- **Locking**: Native GCS generation match locking.

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
