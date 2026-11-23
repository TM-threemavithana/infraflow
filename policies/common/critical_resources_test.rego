package common.critical_resources_test

import rego.v1
import data.common.critical_resources

# --- Test 1: AWS RDS Cluster Deletion Denied ---
test_aws_rds_deletion_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_rds_cluster.primary",
		"type": "aws_rds_cluster",
		"change": {"actions": ["delete"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Direct deletion of critical resource 'aws_rds_cluster.primary'")
}

# --- Test 2: Azure PostgreSQL Server Deletion Denied ---
test_azure_postgres_deletion_denied if {
	mock_plan := {"resource_changes": [{
		"address": "azurerm_postgresql_server.db",
		"type": "azurerm_postgresql_server",
		"change": {"actions": ["delete"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Direct deletion of critical resource 'azurerm_postgresql_server.db'")
}

# --- Test 3: GCP Cloud SQL Instance Deletion Denied ---
test_gcp_sql_deletion_denied if {
	mock_plan := {"resource_changes": [{
		"address": "google_sql_database_instance.main",
		"type": "google_sql_database_instance",
		"change": {"actions": ["delete"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Direct deletion of critical resource 'google_sql_database_instance.main'")
}

# --- Test 4: KMS Key Deletion Denied ---
test_kms_key_deletion_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_kms_key.master",
		"type": "aws_kms_key",
		"change": {"actions": ["delete"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Direct deletion of critical resource 'aws_kms_key.master'")
}

# --- Test 5: Storage Account Deletion Denied ---
test_storage_account_deletion_denied if {
	mock_plan := {"resource_changes": [{
		"address": "azurerm_storage_account.data",
		"type": "azurerm_storage_account",
		"change": {"actions": ["delete"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Direct deletion of critical resource 'azurerm_storage_account.data'")
}

# --- Test 6: IAM Role Deletion Denied ---
test_iam_role_deletion_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_iam_role.app_exec",
		"type": "aws_iam_role",
		"change": {"actions": ["delete"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Direct deletion of critical resource 'aws_iam_role.app_exec'")
}

# --- Test 7: Network Security Group Deletion Denied ---
test_security_group_deletion_denied if {
	mock_plan := {"resource_changes": [{
		"address": "azurerm_network_security_group.frontend",
		"type": "azurerm_network_security_group",
		"change": {"actions": ["delete"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Direct deletion of critical resource 'azurerm_network_security_group.frontend'")
}

# --- Test 8: Destroy-Before-Create Replacement Denied ---
test_destroy_before_create_replacement_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_db_instance.replica",
		"type": "aws_db_instance",
		"change": {"actions": ["delete", "create"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Dangerous destroy-before-create replacement of critical resource 'aws_db_instance.replica'")
}

# --- Test 9: Create-Before-Destroy Replacement Denied ---
test_create_before_destroy_replacement_denied if {
	mock_plan := {"resource_changes": [{
		"address": "google_kms_crypto_key.app_key",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create", "delete"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Create-before-destroy replacement of critical resource 'google_kms_crypto_key.app_key'")
}

# --- Test 10: Generic Confirmation Token "yes" Denied ---
test_generic_token_yes_denied if {
	mock_plan := {
		"resource_changes": [{
			"address": "aws_kms_key.master",
			"type": "aws_kms_key",
			"change": {"actions": ["delete"]},
		}],
		"infraflow_authorization": {
			"authorized": true,
			"token": "yes",
		},
	}
	res := critical_resources.deny with input as mock_plan
	count(res) >= 1
	contains(res[_], "Generic confirmation token 'yes' is rejected")
}

# --- Test 11: Generic Confirmation Token "force" Denied ---
test_generic_token_force_denied if {
	mock_plan := {
		"resource_changes": [{
			"address": "aws_kms_key.master",
			"type": "aws_kms_key",
			"change": {"actions": ["delete"]},
		}],
		"infraflow_authorization": {
			"authorized": true,
			"token": "force",
		},
	}
	res := critical_resources.deny with input as mock_plan
	count(res) >= 1
	contains(res[_], "Generic confirmation token 'force' is rejected")
}

# --- Test 12: Cryptographically Authorized Destruction Allowed ---
test_authorized_plan_allowed if {
	mock_plan := {
		"resource_changes": [{
			"address": "aws_db_instance.decommission",
			"type": "aws_db_instance",
			"change": {"actions": ["delete"]},
		}],
		"infraflow_authorization": {
			"authorized": true,
			"schema_version": "infraflow-destruction-confirmation-v1",
			"token": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
	res := critical_resources.deny with input as mock_plan
	count(res) == 0
}

# --- Test 13: Non-Critical Resource Deletion Allowed ---
test_non_critical_deletion_allowed if {
	mock_plan := {"resource_changes": [{
		"address": "aws_route53_record.temp_cname",
		"type": "aws_route53_record",
		"change": {"actions": ["delete"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 0
}

# --- Test 14: Safe Resource Creation Allowed ---
test_safe_create_update_allowed if {
	mock_plan := {"resource_changes": [
		{
			"address": "aws_db_instance.new_db",
			"type": "aws_db_instance",
			"change": {"actions": ["create"]},
		},
		{
			"address": "azurerm_storage_account.new_sa",
			"type": "azurerm_storage_account",
			"change": {"actions": ["update"]},
		},
	]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 0
}

# --- Test 15: Unknown Action Token Denied ---
test_unknown_action_token_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket.bad_action",
		"type": "aws_s3_bucket",
		"change": {"actions": ["purge_all_data"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "contains unknown or unsupported action token 'purge_all_data'")
}

# --- Test 16: Malformed Plan Missing Changes Denied ---
test_malformed_plan_missing_changes_denied if {
	mock_plan := {"format_version": "1.2"}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Plan JSON is missing 'resource_changes' array")
}

# --- Test 17: Malformed Resource Null Change Denied ---
test_malformed_resource_null_change_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_kms_key.corrupt",
		"type": "aws_kms_key",
		"change": null,
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "contains null or missing change block")
}

# --- Test 18: Unauthorized Decommissioning Rejected (Audit Finding AC-G10.3.1) ---
test_unauthorized_decommission_denied if {
	mock_plan := {"resource_changes": [{
		"address": "aws_s3_bucket.decommissioned_bucket",
		"type": "aws_s3_bucket",
		"change": {"actions": ["delete"]},
	}]}
	res := critical_resources.deny with input as mock_plan
	count(res) == 1
	contains(res[_], "Direct deletion of critical resource 'aws_s3_bucket.decommissioned_bucket'")
}

# --- Test 19: Authorized Decommissioning Allowed With Plan-Bound Token ---
test_authorized_decommission_allowed if {
	mock_plan := {
		"resource_changes": [{
			"address": "aws_s3_bucket.decommissioned_bucket",
			"type": "aws_s3_bucket",
			"change": {"actions": ["delete"]},
		}],
		"infraflow_authorization": {
			"authorized": true,
			"schema_version": "infraflow-destruction-confirmation-v1",
			"token": "infraflow-authorized-decommission-audit-token-v1",
		},
	}
	res := critical_resources.deny with input as mock_plan
	count(res) == 0
}
