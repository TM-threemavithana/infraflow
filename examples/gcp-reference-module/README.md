# InfraFlow Google Cloud Reference Module

This reference module demonstrates enterprise-grade infrastructure configuration for Google Cloud Platform (GCP) state management and resource provisioning within the InfraFlow DevSecOps pipeline.

## Architectural Capabilities

1. **Zero Cloud Spend ($0.00)**: Completely operational without a Google Cloud billing account, service project, or paid services.
2. **Zero Credentials**: Requires no service account keys, OAuth access tokens, or live cloud access.
3. **Mock Provider Testing**: Uses native Terraform `>= 1.7.0` provider mocking (`mock_provider "google" {}`) for 100% offline, deterministic CI/CD validation.
4. **DevSecOps Policy Compliance**:
   - Uniform Bucket-Level Access (UBLA) enforced (CIS GCP 5.2).
   - Public Access Prevention (`enforced`) enabled (CIS GCP 5.1).
   - Object Versioning enabled for state resilience.
   - Accidental Destruction Protection (`force_destroy = false`).
   - Customer-Managed Encryption Keys (CMEK) via Cloud KMS.
   - Mandatory governance labels (`environment`, `managed_by`, `project`).

## Verification Commands

Validate the module locally without cloud credentials:

```bash
# Format check
terraform fmt -check

# Backend-free initialization
terraform init -backend=false

# Static schema and constraint validation
terraform validate

# Native mock-provider unit test execution (requires Terraform >= 1.7.0)
terraform test
```
