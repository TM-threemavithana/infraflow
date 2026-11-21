package azure.storage_backend_test

import rego.v1
import data.azure.storage_backend

# 1. Valid Azure Backend Allowed
test_valid_backend_allowed if {
	mock_input := {"backend": {"azurerm": {
		"resource_group_name": "rg-infraflow-prod",
		"storage_account_name": "stinfraflowprod01",
		"container_name": "tfstate",
		"key": "prod/terraform.tfstate",
		"use_azuread_auth": true,
	}}}
	res := storage_backend.deny with input as mock_input
	count(res) == 0
}

# 2. Invalid Storage Account Name Denied
test_invalid_storage_account_name_denied if {
	mock_input := {"backend": {"azurerm": {
		"storage_account_name": "Bad_Storage_Account_Name",
		"resource_group_name": "rg-infraflow",
		"container_name": "tfstate",
		"key": "prod/terraform.tfstate",
		"use_azuread_auth": true,
	}}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must be 3-24 lowercase alphanumeric characters only")
}

# 3. Invalid Resource Group Name Denied (ends with dot)
test_invalid_rg_name_denied if {
	mock_input := {"backend": {"azurerm": {
		"storage_account_name": "stinfraflowprod01",
		"resource_group_name": "invalid-rg.",
		"container_name": "tfstate",
		"key": "prod/terraform.tfstate",
		"use_azuread_auth": true,
	}}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "contains invalid characters or ends with a period")
}

# 4. Invalid Container Name Denied (consecutive hyphens)
test_invalid_container_name_denied if {
	mock_input := {"backend": {"azurerm": {
		"storage_account_name": "stinfraflowprod01",
		"resource_group_name": "rg-prod",
		"container_name": "bad--container",
		"key": "prod/terraform.tfstate",
		"use_azuread_auth": true,
	}}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "violates Azure Blob container naming rules")
}

# 5. Empty Key Denied
test_empty_key_denied if {
	mock_input := {"backend": {"azurerm": {
		"storage_account_name": "stinfraflowprod01",
		"resource_group_name": "rg-prod",
		"container_name": "tfstate",
		"key": "",
		"use_azuread_auth": true,
	}}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must not be empty")
}

# 6. Leading Slash Key Denied
test_leading_slash_key_denied if {
	mock_input := {"backend": {"azurerm": {
		"storage_account_name": "stinfraflowprod01",
		"resource_group_name": "rg-prod",
		"container_name": "tfstate",
		"key": "/prod/terraform.tfstate",
		"use_azuread_auth": true,
	}}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must not contain leading slash")
}

# 7. Path Traversal Key Denied
test_path_traversal_key_denied if {
	mock_input := {"backend": {"azurerm": {
		"storage_account_name": "stinfraflowprod01",
		"resource_group_name": "rg-prod",
		"container_name": "tfstate",
		"key": "../../secret/terraform.tfstate",
		"use_azuread_auth": true,
	}}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "forbidden path traversal '..'")
}

# 8. Missing Entra ID Auth Denied (no use_azuread_auth or use_oidc)
test_missing_entra_id_auth_denied if {
	mock_input := {"backend": {"azurerm": {
		"storage_account_name": "stinfraflowprod01",
		"resource_group_name": "rg-prod",
		"container_name": "tfstate",
		"key": "prod/terraform.tfstate",
		"use_azuread_auth": false,
		"use_oidc": false,
	}}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must enable Microsoft Entra ID authentication")
}

# 9. Static Storage Access Key Denied
test_static_access_key_denied if {
	mock_input := {"backend": {"azurerm": {
		"storage_account_name": "stinfraflowprod01",
		"resource_group_name": "rg-prod",
		"container_name": "tfstate",
		"key": "prod/terraform.tfstate",
		"use_azuread_auth": true,
		"access_key": "raw-secret-key-12345",
	}}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "specifies static 'access_key'")
}

# 10. Public Blob Access on Storage Account Denied
test_public_blob_access_denied if {
	mock_input := {"storage_account": {
		"name": "stinfraflowprod01",
		"allow_nested_items_to_be_public": true,
		"min_tls_version": "TLS1_2",
	}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must not set allow_nested_items_to_be_public to true")
}

# 11. Public Access on Container Denied
test_public_container_access_denied if {
	mock_input := {"container": {
		"name": "tfstate",
		"container_access_type": "blob",
	}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must enforce 'container_access_type = private'")
}

# 12. Insecure TLS Version Denied
test_insecure_tls_denied if {
	mock_input := {"storage_account": {
		"name": "stinfraflowprod01",
		"allow_nested_items_to_be_public": false,
		"min_tls_version": "TLS1_0",
	}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "min_tls_version must explicitly be 'TLS1_2' or 'TLS1_3'")
}

# 13. Unrestricted Public Network Access Denied
test_public_network_access_denied if {
	mock_input := {"storage_account": {
		"name": "stinfraflowprod01",
		"allow_nested_items_to_be_public": false,
		"min_tls_version": "TLS1_2",
		"public_network_access_enabled": true,
		"network_rules": [],
	}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must disable unrestricted public network access")
}

# 14. Shared Access Key Enabled on Storage Account Denied
test_shared_access_key_enabled_denied if {
	mock_input := {"storage_account": {
		"name": "stinfraflowprod01",
		"allow_nested_items_to_be_public": false,
		"min_tls_version": "TLS1_2",
		"public_network_access_enabled": false,
		"shared_access_key_enabled": true,
	}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "disable shared access keys")
}

# 15. Missing Blob Versioning on State Storage Denied
test_missing_blob_versioning_denied if {
	mock_input := {"storage_account": {
		"name": "stinfraflowprod01",
		"allow_nested_items_to_be_public": false,
		"min_tls_version": "TLS1_2",
		"public_network_access_enabled": false,
		"shared_access_key_enabled": false,
		"tags": {"project": "infraflow"},
		"blob_properties": {"versioning_enabled": false},
	}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must enable blob versioning")
}

# 16. Overprivileged Storage Role Assignment Denied
test_storage_owner_role_denied if {
	mock_input := {"role_assignments": [{
		"role_definition_name": "Owner",
		"scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stinfraflowprod01",
		"principal_id": "00000000-0000-0000-0000-000000000000",
	}]}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "Overprivileged role 'Owner' granted on storage scope")
}

# 17. Least Privilege Storage Data Contributor Role Allowed
test_storage_data_contributor_allowed if {
	mock_input := {"role_assignments": [{
		"role_definition_name": "Storage Blob Data Contributor",
		"scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stinfraflowprod01",
		"principal_id": "00000000-0000-0000-0000-000000000000",
	}]}
	res := storage_backend.deny with input as mock_input
	count(res) == 0
}

# 18. Root Level State Key Without Environment Namespace Denied
test_root_state_key_denied if {
	mock_input := {"backend": {"azurerm": {
		"storage_account_name": "stinfraflowprod01",
		"resource_group_name": "rg-prod",
		"container_name": "tfstate",
		"key": "terraform.tfstate",
		"use_azuread_auth": true,
	}}}
	res := storage_backend.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must include an environment namespace")
}
