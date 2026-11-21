# InfraFlow Microsoft Azure Reference Architecture Module

This module provides a hardened, reference-grade baseline for provisioning Microsoft Azure resources within the InfraFlow ecosystem. It complies with ISO/IEC 27001, NIST SP 800-218 (SSDF), and the CIS Microsoft Azure Foundation Benchmark.

## Features & Security Controls

- **Microsoft Entra ID Passwordless OIDC:** Configured for OpenID Connect workload identity federation (`use_oidc = true`). No long-lived service principal client secrets or certificates are required.
- **Secure Azure Blob Storage:**
  - `min_tls_version = "TLS1_2"` enforced.
  - `allow_nested_items_to_be_public = false` prevents public anonymous blob accessibility.
  - `public_network_access_enabled = false` restricts direct internet access.
  - `shared_access_key_enabled = false` mandates Entra ID data-plane authentication and disables SAS/key fallbacks.
  - `infrastructure_encryption_enabled = true` enables double encryption for high-assurance data at rest.
  - `blob_properties.versioning_enabled = true` enables state blob versioning.
  - `container_access_type = "private"` ensures all blobs are strictly access-controlled.

## Offline Testing with Native Mock Provider

This module uses native Terraform 1.7+ mock provider testing (`mock_provider "azurerm" {}`) to validate HCL structure, variable propagation, and compliance assertions without executing Azure API calls or requiring cloud credentials ($0.00 spend).

```bash
# Initialize module in backend-free mode
terraform init -backend=false

# Execute native offline unit tests
terraform test -verbose
```
