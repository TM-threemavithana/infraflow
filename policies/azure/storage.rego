package azure.storage

import rego.v1

# Rule 1: Deny storage account with public blob access enabled
deny contains msg if {
	some name
	sa := input.resource.azurerm_storage_account[name][_]
	object.get(sa, "allow_nested_items_to_be_public", false) == true
	msg := sprintf("Resource 'azurerm_storage_account.%v' must not set allow_nested_items_to_be_public to true", [name])
}

# Rule 2: Deny storage account unless min_tls_version is explicitly TLS1_2
deny contains msg if {
	some name
	sa := input.resource.azurerm_storage_account[name][_]
	object.get(sa, "min_tls_version", "") != "TLS1_2"
	msg := sprintf("Resource 'azurerm_storage_account.%v' min_tls_version must explicitly be 'TLS1_2'", [name])
}
