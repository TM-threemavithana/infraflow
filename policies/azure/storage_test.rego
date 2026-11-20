package azure.storage_test

import rego.v1
import data.azure.storage

test_storage_public_access_denied if {
	mock_input := {"resource": {"azurerm_storage_account": {"bad_sa": [{
		"allow_nested_items_to_be_public": true,
		"min_tls_version": "TLS1_2",
	}]}}}
	res := storage.deny with input as mock_input
	count(res) == 1
	contains(res[_], "must not set allow_nested_items_to_be_public to true")
}

test_storage_insecure_tls_denied if {
	mock_input := {"resource": {"azurerm_storage_account": {"bad_sa": [{
		"allow_nested_items_to_be_public": false,
		"min_tls_version": "TLS1_0",
	}]}}}
	res := storage.deny with input as mock_input
	count(res) == 1
	contains(res[_], "min_tls_version must explicitly be 'TLS1_2'")
}

test_storage_omitted_tls_denied if {
	mock_input := {"resource": {"azurerm_storage_account": {"bad_sa": [{
		"allow_nested_items_to_be_public": false,
	}]}}}
	res := storage.deny with input as mock_input
	count(res) >= 1
}

test_storage_secure_allowed if {
	mock_input := {"resource": {"azurerm_storage_account": {"good_sa": [{
		"allow_nested_items_to_be_public": false,
		"min_tls_version": "TLS1_2",
	}]}}}
	res := storage.deny with input as mock_input
	count(res) == 0
}
