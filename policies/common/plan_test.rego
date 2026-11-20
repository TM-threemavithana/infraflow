package common.plan_test

import rego.v1
import data.common.plan

# --- Category 1: Public / Insecure Resource Configurations in Plan ---

test_plan_public_s3_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket.bad_plan",
		"type": "aws_s3_bucket",
		"change": {
			"actions": ["create"],
			"after": {"acl": "public-read"},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "specifies public ACL 'public-read'")
}

test_plan_module_contained_s3_denied if {
	mock_plan := {"resource_changes": [{
		"address": "module.storage_layer.aws_s3_bucket.child_data",
		"type": "aws_s3_bucket",
		"change": {
			"actions": ["create"],
			"after": {"acl": "public-read"},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "module.storage_layer.aws_s3_bucket.child_data")
}

# --- Category 2: Unknown Security Attributes (after_unknown) ---

test_plan_unknown_acl_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket.unknown_acl",
		"type": "aws_s3_bucket",
		"change": {
			"actions": ["create"],
			"after": {},
			"after_unknown": {"acl": true},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "unknown/computed ACL")
}

test_plan_unknown_pab_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.unknown_pab",
		"type": "aws_s3_bucket_public_access_block",
		"change": {
			"actions": ["create"],
			"after": {
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			},
			"after_unknown": {"block_public_acls": true},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "unknown/computed block_public_acls")
}

test_plan_unknown_tls_denied if {
	mock_plan := {"resource_changes": [{
		"address": "azurerm_storage_account.unknown_tls",
		"type": "azurerm_storage_account",
		"change": {
			"actions": ["create"],
			"after": {},
			"after_unknown": {"min_tls_version": true},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "unknown min_tls_version")
}

test_plan_unknown_gcp_uniform_denied if {
	mock_plan := {"resource_changes": [{
		"address": "google_storage_bucket.unknown_uniform",
		"type": "google_storage_bucket",
		"change": {
			"actions": ["create"],
			"after": {},
			"after_unknown": {"uniform_bucket_level_access": true},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "unknown uniform_bucket_level_access")
}

# --- Category 3: Security Control Deletions ---

test_plan_deleted_s3_pab_denied_when_parent_active if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.unprotected",
		"type": "aws_s3_bucket_public_access_block",
		"change": {
			"actions": ["delete"],
			"before": {"bucket": "active-prod-bucket", "block_public_acls": true},
			"after": null,
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Deletion of critical security control 'aws_s3_bucket_public_access_block.unprotected'")
}

test_plan_deleted_s3_encryption_denied_when_parent_active if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.stripped_enc",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {
			"actions": ["delete"],
			"before": {"bucket": "active-prod-bucket"},
			"after": null,
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Deletion of critical security control 'aws_s3_bucket_server_side_encryption_configuration.stripped_enc'")
}

test_plan_deleted_azure_network_rules_denied_when_parent_active if {
	mock_plan := {"resource_changes": [{
		"address": "azurerm_storage_account_network_rules.exposed_rules",
		"type": "azurerm_storage_account_network_rules",
		"change": {
			"actions": ["delete"],
			"before": {"storage_account_name": "activecorpstorage"},
			"after": null,
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Deletion of critical security control 'azurerm_storage_account_network_rules.exposed_rules'")
}

test_plan_deleted_s3_policy_denied_when_parent_active if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket_policy.removed_policy",
		"type": "aws_s3_bucket_policy",
		"change": {
			"actions": ["delete"],
			"before": {"bucket": "active-prod-bucket"},
			"after": null,
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Deletion of critical security control 'aws_s3_bucket_policy.removed_policy'")
}

test_plan_deleted_security_control_allowed_when_parent_also_deleted if {
	mock_plan := {"resource_changes": [
		{
			"address": "aws_s3_bucket_public_access_block.decommissioned_pab",
			"type": "aws_s3_bucket_public_access_block",
			"change": {
				"actions": ["delete"],
				"before": {"bucket": "decommissioned-bucket"},
				"after": null,
			},
		},
		{
			"address": "aws_s3_bucket.decommissioned_bucket",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["delete"],
				"before": {"bucket": "decommissioned-bucket"},
				"after": null,
			},
		},
	]}
	res := plan.deny with input as mock_plan
	count(res) == 0
}

test_plan_deleted_s3_pab_denied_when_different_bucket_deleted if {
	mock_plan := {"resource_changes": [
		{
			"address": "aws_s3_bucket_public_access_block.pab_a",
			"type": "aws_s3_bucket_public_access_block",
			"change": {
				"actions": ["delete"],
				"before": {"bucket": "bucket-alpha"},
				"after": null,
			},
		},
		{
			"address": "aws_s3_bucket.bucket_b",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["delete"],
				"before": {"bucket": "bucket-beta"},
				"after": null,
			},
		},
	]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Deletion of critical security control 'aws_s3_bucket_public_access_block.pab_a'")
}

test_plan_deleted_s3_pab_denied_when_different_module_bucket_deleted if {
	mock_plan := {"resource_changes": [
		{
			"address": "module.tenant_a.aws_s3_bucket_public_access_block.pab",
			"module_address": "module.tenant_a",
			"type": "aws_s3_bucket_public_access_block",
			"change": {
				"actions": ["delete"],
				"before": {"bucket": "shared-bucket-name"},
				"after": null,
			},
		},
		{
			"address": "module.tenant_b.aws_s3_bucket.bucket",
			"module_address": "module.tenant_b",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["delete"],
				"before": {"bucket": "shared-bucket-name"},
				"after": null,
			},
		},
	]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Deletion of critical security control 'module.tenant_a.aws_s3_bucket_public_access_block.pab'")
}

test_plan_deleted_azure_network_rules_allowed_when_parent_also_deleted if {
	mock_plan := {"resource_changes": [
		{
			"address": "azurerm_storage_account_network_rules.rules",
			"type": "azurerm_storage_account_network_rules",
			"change": {
				"actions": ["delete"],
				"before": {"storage_account_name": "decommsa"},
				"after": null,
			},
		},
		{
			"address": "azurerm_storage_account.sa",
			"type": "azurerm_storage_account",
			"change": {
				"actions": ["delete"],
				"before": {"name": "decommsa"},
				"after": null,
			},
		},
	]}
	res := plan.deny with input as mock_plan
	count(res) == 0
}

test_plan_deleted_azure_network_rules_denied_when_different_storage_account_deleted if {
	mock_plan := {"resource_changes": [
		{
			"address": "azurerm_storage_account_network_rules.rules_a",
			"type": "azurerm_storage_account_network_rules",
			"change": {
				"actions": ["delete"],
				"before": {"storage_account_name": "storage-alpha"},
				"after": null,
			},
		},
		{
			"address": "azurerm_storage_account.sa_b",
			"type": "azurerm_storage_account",
			"change": {
				"actions": ["delete"],
				"before": {"name": "storage-beta"},
				"after": null,
			},
		},
	]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Deletion of critical security control 'azurerm_storage_account_network_rules.rules_a'")
}

test_plan_deleted_azure_network_rules_denied_when_different_module_storage_account_deleted if {
	mock_plan := {"resource_changes": [
		{
			"address": "module.tenant_a.azurerm_storage_account_network_rules.rules",
			"module_address": "module.tenant_a",
			"type": "azurerm_storage_account_network_rules",
			"change": {
				"actions": ["delete"],
				"before": {"storage_account_name": "shared-storage"},
				"after": null,
			},
		},
		{
			"address": "module.tenant_b.azurerm_storage_account.sa",
			"module_address": "module.tenant_b",
			"type": "azurerm_storage_account",
			"change": {
				"actions": ["delete"],
				"before": {"name": "shared-storage"},
				"after": null,
			},
		},
	]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Deletion of critical security control 'module.tenant_a.azurerm_storage_account_network_rules.rules'")
}

test_plan_safe_delete_ordinary_resource_allowed if {
	mock_plan := {"resource_changes": [{
		"address": "aws_instance.decommissioned_worker",
		"type": "aws_instance",
		"change": {
			"actions": ["delete"],
			"before": {"ami": "ami-12345"},
			"after": null,
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 0
}

# --- Category 4: Replacement Actions (Both Ordering Sequences) ---

test_plan_replace_security_control_insecure_delete_create_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.replaced_pab_dc",
		"type": "aws_s3_bucket_public_access_block",
		"change": {
			"actions": ["delete", "create"],
			"before": {"bucket": "corp-data", "block_public_acls": true},
			"after": {
				"bucket": "corp-data",
				"block_public_acls": false,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "must set block_public_acls to true")
}

test_plan_replace_security_control_insecure_create_delete_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.replaced_pab_cd",
		"type": "aws_s3_bucket_public_access_block",
		"change": {
			"actions": ["create", "delete"],
			"before": {"bucket": "corp-data", "block_public_acls": true},
			"after": {
				"bucket": "corp-data",
				"block_public_acls": false,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "must set block_public_acls to true")
}

test_plan_replace_security_control_secure_delete_create_allowed if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.replaced_secure_pab_dc",
		"type": "aws_s3_bucket_public_access_block",
		"change": {
			"actions": ["delete", "create"],
			"before": {"bucket": "corp-data", "block_public_acls": true},
			"after": {
				"bucket": "corp-data",
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 0
}

test_plan_replace_security_control_secure_create_delete_allowed if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket_public_access_block.replaced_secure_pab_cd",
		"type": "aws_s3_bucket_public_access_block",
		"change": {
			"actions": ["create", "delete"],
			"before": {"bucket": "corp-data", "block_public_acls": true},
			"after": {
				"bucket": "corp-data",
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 0
}

# --- Category 5: Incomplete or Errored Plan Inputs ---

test_plan_errored_plan_denied if {
	mock_plan := {
		"format_version": "1.2",
		"errored": true,
		"resource_changes": [],
	}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "indicates errors during plan generation")
}

test_plan_missing_resource_changes_denied if {
	mock_plan := {
		"format_version": "1.2",
		"terraform_version": "1.10.4",
	}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "missing 'resource_changes' array")
}

test_plan_null_change_block_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket.corrupted_node",
		"type": "aws_s3_bucket",
		"change": null,
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "null or missing change block")
}

# --- Category 6: Valid Standard Resources Allowed ---

test_plan_valid_s3_allowed if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket.good_plan",
		"type": "aws_s3_bucket",
		"change": {
			"actions": ["create"],
			"after": {"acl": "private"},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 0
}

test_plan_azure_valid_storage_allowed if {
	mock_plan := {"resource_changes": [{
		"address": "azurerm_storage_account.good_sa",
		"type": "azurerm_storage_account",
		"change": {
			"actions": ["create"],
			"after": {
				"allow_nested_items_to_be_public": false,
				"min_tls_version": "TLS1_2",
			},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 0
}

test_plan_gcp_valid_storage_allowed if {
	mock_plan := {"resource_changes": [{
		"address": "google_storage_bucket.good_gcs",
		"type": "google_storage_bucket",
		"change": {
			"actions": ["create"],
			"after": {"uniform_bucket_level_access": true},
		},
	}]}
	res := plan.deny with input as mock_plan
	count(res) == 0
}
