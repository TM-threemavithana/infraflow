package common.tags_test

import rego.v1
import data.common.tags

# --- Taggable resources with missing metadata blocks ---

test_aws_taggable_missing_tags_denied if {
	mock_input := {"resource": {"aws_s3_bucket": {"unlabeled": [{"bucket": "test-bucket"}]}}}
	res := tags.deny with input as mock_input
	count(res) == 1
	contains(res[_], "missing mandatory 'tags' block")
}

test_azure_taggable_missing_tags_denied if {
	mock_input := {"resource": {"azurerm_storage_account": {"sa": [{"name": "testsa"}]}}}
	res := tags.deny with input as mock_input
	count(res) == 1
	contains(res[_], "missing mandatory 'tags' block")
}

test_gcp_labelable_missing_labels_denied if {
	mock_input := {"resource": {"google_storage_bucket": {"bucket": [{"name": "test-bucket"}]}}}
	res := tags.deny with input as mock_input
	count(res) == 1
	contains(res[_], "missing mandatory 'labels' block")
}

# --- Missing mandatory attributes ---

test_aws_missing_environment_tag_denied if {
	mock_input := {"resource": {"aws_s3_bucket": {"bad": [{"tags": {"Project": "infraflow", "ManagedBy": "terraform"}}]}}}
	res := tags.deny with input as mock_input
	count(res) == 1
	contains(res[_], "missing mandatory tag 'Environment'")
}

test_gcp_missing_environment_label_denied if {
	mock_input := {"resource": {"google_storage_bucket": {"bad": [{"labels": {"project": "infraflow", "managed_by": "terraform"}}]}}}
	res := tags.deny with input as mock_input
	count(res) == 1
	contains(res[_], "missing mandatory label 'Environment'")
}

test_aws_missing_managed_by_tag_denied if {
	mock_input := {"resource": {"aws_s3_bucket": {"bad": [{"tags": {"Environment": "dev", "Project": "infraflow"}}]}}}
	res := tags.deny with input as mock_input
	count(res) == 1
	contains(res[_], "missing mandatory tag 'ManagedBy'")
}

test_gcp_missing_managed_by_label_denied if {
	mock_input := {"resource": {"google_storage_bucket": {"bad": [{"labels": {"environment": "dev", "project": "infraflow"}}]}}}
	res := tags.deny with input as mock_input
	count(res) == 1
	contains(res[_], "missing mandatory label 'ManagedBy'")
}

test_aws_missing_project_tag_denied if {
	mock_input := {"resource": {"aws_s3_bucket": {"bad": [{"tags": {"Environment": "dev", "ManagedBy": "terraform"}}]}}}
	res := tags.deny with input as mock_input
	count(res) == 1
	contains(res[_], "missing mandatory tag 'Project'")
}

test_gcp_missing_project_label_denied if {
	mock_input := {"resource": {"google_storage_bucket": {"bad": [{"labels": {"environment": "dev", "managed_by": "terraform"}}]}}}
	res := tags.deny with input as mock_input
	count(res) == 1
	contains(res[_], "missing mandatory label 'Project'")
}

# --- Invalid environment values ---

test_invalid_environment_tag_denied if {
	mock_input := {"resource": {"aws_s3_bucket": {"bad": [{"tags": {"Environment": "local-hacked", "Project": "infraflow", "ManagedBy": "terraform"}}]}}}
	res := tags.deny with input as mock_input
	count(res) == 1
	contains(res[_], "has invalid Environment 'local-hacked'")
}

test_invalid_environment_label_denied if {
	mock_input := {"resource": {"google_storage_bucket": {"bad": [{"labels": {"environment": "invalid-env", "project": "infraflow", "managed_by": "terraform"}}]}}}
	res := tags.deny with input as mock_input
	count(res) == 1
	contains(res[_], "has invalid Environment 'invalid-env'")
}

# --- Valid metadata accepted ---

test_aws_valid_tags_allowed if {
	mock_input := {"resource": {"aws_s3_bucket": {"good": [{"tags": {"Environment": "prod", "Project": "infraflow", "ManagedBy": "terraform"}}]}}}
	res := tags.deny with input as mock_input
	count(res) == 0
}

test_azure_valid_tags_allowed if {
	mock_input := {"resource": {"azurerm_storage_account": {"good": [{"tags": {"Environment": "staging", "Project": "infraflow", "ManagedBy": "terraform"}}]}}}
	res := tags.deny with input as mock_input
	count(res) == 0
}

test_gcp_valid_labels_allowed if {
	mock_input := {"resource": {"google_storage_bucket": {"good": [{"labels": {"environment": "prod", "project": "infraflow", "managed_by": "terraform"}}]}}}
	res := tags.deny with input as mock_input
	count(res) == 0
}

# --- Unsupported resources legitimately without tags/labels (zero false positives) ---

test_aws_unsupported_resource_without_tags_allowed if {
	mock_input := {"resource": {
		"aws_route_table_association": {"assoc": [{"route_table_id": "rtb-123", "subnet_id": "subnet-123"}]},
		"aws_s3_bucket_public_access_block": {"pab": [{"bucket": "my-bucket", "block_public_acls": true}]},
	}}
	res := tags.deny with input as mock_input
	count(res) == 0
}

test_azure_unsupported_resource_without_tags_allowed if {
	mock_input := {"resource": {"azurerm_subnet_network_security_group_association": {"assoc": [{
		"subnet_id": "sub-123",
		"network_security_group_id": "nsg-123",
	}]}}}
	res := tags.deny with input as mock_input
	count(res) == 0
}

test_gcp_unsupported_resource_without_labels_allowed if {
	mock_input := {"resource": {
		"google_compute_network": {"net": [{"name": "vpc-network", "auto_create_subnetworks": false}]},
		"google_compute_firewall": {"fw": [{"name": "allow-ssh", "network": "vpc-network"}]},
	}}
	res := tags.deny with input as mock_input
	count(res) == 0
}

test_non_cloud_resource_without_tags_allowed if {
	mock_input := {"resource": {"terraform_data": {"local_node": [{"input": "test"}]}}}
	res := tags.deny with input as mock_input
	count(res) == 0
}
