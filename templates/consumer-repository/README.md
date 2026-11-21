# InfraFlow Consumer Repository Template

This template provides a production-grade, secure starting point for any repository adopting **InfraFlow**.

---

## What Is Included

```
.
├── .github/
│   └── workflows/
│       └── infraflow.yml          # GitHub Actions caller workflow
├── terraform/                     # Cloud-free reference Terraform module
│   ├── main.tf                    # Core HCL resources (terraform_data)
│   ├── variables.tf               # Validated module variables
│   ├── outputs.tf                 # Standardized module outputs
│   ├── versions.tf                # Terraform CLI >= 1.6.0 constraint
│   └── tests/
│       └── unit.tftest.hcl        # Native offline unit tests
├── infraflow.config.yaml          # Consumer configuration contract
└── README.md                      # Consumer onboarding instructions
```

---

## Quick Start (3 Steps)

### 1. Update Repository Settings in `infraflow.config.yaml`
Edit `infraflow.config.yaml` to specify your repository identity, owning team, and workload type:
```yaml
consumer_id: "my-service-repo"
team: "my-team"
workload_type: "application" # networking | application | data-platform | general
terraform_dir: "terraform"
environment: "dev"
adapter: "provider-neutral" # provider-neutral | aws | gcp | azure | apply-simulation
platform_sha: "2ce0ddd5de01530b6bf7aba749f0081620fb9b27" # v0.5.0
```

### 2. Verify Your Configuration Locally
Before pushing to GitHub, run the InfraFlow consumer validation tool:
```bash
python3 /path/to/infraflow/scripts/validate-consumer.py --config infraflow.config.yaml --repo-dir .
```

### 3. Commit and Open a Pull Request
Push your branch to GitHub. InfraFlow will automatically validate your code on pull request with zero cloud credentials.

---

## Reusable Workflow Integration Options

Choose the reusable workflow that matches your workload and update `.github/workflows/infraflow.yml`:

### Option 1: Provider-Neutral Validation Core (Default)
Executes `terraform fmt -check`, `terraform init -backend=false`, `terraform validate`, and native `terraform test`:
```yaml
jobs:
  validate:
    name: "Validate Terraform"
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-validate.yml@2ce0ddd5de01530b6bf7aba749f0081620fb9b27
    with:
      terraform-version: "1.10.4"
      working-directory: "terraform"
      enable-fmt-check: true
      enable-validate: true
      enable-test: true
```

### Option 2: AWS Cloud-Free Adapter
Executes AWS speculative planning and S3 backend security policy evaluation:
```yaml
jobs:
  aws-plan:
    name: "AWS Speculative Plan (Cloud-Free)"
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-aws.yml@2ce0ddd5de01530b6bf7aba749f0081620fb9b27
    with:
      terraform-version: "1.10.4"
      working-directory: "terraform"
      environment: "dev"
      s3-bucket: "my-infra-tfstate"
      s3-key: "env/dev/terraform.tfstate"
      enable-aws-auth: false
```

### Option 3: GCP Cloud-Free Adapter
Executes GCP speculative planning and GCS backend security policy evaluation:
```yaml
jobs:
  gcp-plan:
    name: "GCP Speculative Plan (Cloud-Free)"
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-gcp.yml@2ce0ddd5de01530b6bf7aba749f0081620fb9b27
    with:
      terraform-version: "1.10.4"
      working-directory: "terraform"
      environment: "dev"
      gcs-bucket: "my-infra-tfstate"
      gcs-prefix: "env/dev"
      enable-gcp-auth: false
```

### Option 4: Azure Cloud-Free Adapter
Executes Azure speculative planning and Azure Blob backend security policy evaluation:
```yaml
jobs:
  azure-plan:
    name: "Azure Speculative Plan (Cloud-Free)"
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-azure.yml@2ce0ddd5de01530b6bf7aba749f0081620fb9b27
    with:
      terraform-version: "1.10.4"
      working-directory: "terraform"
      environment: "dev"
      storage-account-name: "mystorageacct"
      container-name: "tfstate"
      state-key: "env/dev/terraform.tfstate"
      enable-azure-auth: false
```

### Option 5: Protected Execution Simulation (G06)
Executes cryptographically verified plan simulation with envelope encryption and replay defense:
```yaml
jobs:
  apply-simulation:
    name: "Protected Apply Simulation"
    uses: TM-threemavithana/infraflow/.github/workflows/reusable-tf-apply.yml@2ce0ddd5de01530b6bf7aba749f0081620fb9b27
    with:
      terraform-version: "1.10.4"
      working-directory: "terraform"
      environment: "dev"
      run-positive-simulation: true
```

---

## Security Invariants & Permission Policy

- **Workflow Permissions**: Must be explicitly set to `permissions: contents: read`. Never configure `write-all` or elevated permissions.
- **Zero Cloud Credentials**: Never store or pass AWS Access Keys, GCP Service Account keys, or Azure secrets in PR checks.
- **Immutable Pinning**: Always pin reusable workflows using full 40-character commit SHAs (`@2ce0ddd5de01530b6bf7aba749f0081620fb9b27`), never mutable branch names (`@main`).
