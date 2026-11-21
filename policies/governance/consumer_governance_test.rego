package governance.consumer_test

import rego.v1
import data.governance.consumer

# Base Valid Networking Payload
valid_networking_payload := {
	"version": "1.0",
	"consumer_id": "consumer-networking",
	"team": "platform-networking",
	"workload_type": "networking",
	"environment": "dev",
	"adapter": "aws",
	"platform_ref": "TM-threemavithana/infraflow",
	"platform_sha": "8fd761bb42165435e1162f37ee39df15d5532b09",
	"terraform_version": "1.10.4",
	"terraform_dir": "terraform",
	"security_controls": {
		"enforce_mandatory_scanners": true,
		"fail_on_destructive": false,
		"max_allowed_deletions": 10,
	},
	"workflow_calls": [{
		"workflow_file": "infraflow-ci.yml",
		"job_id": "aws-speculative-plan",
		"platform_repo": "TM-threemavithana/infraflow",
		"platform_workflow": "reusable-tf-aws.yml",
		"platform_sha": "8fd761bb42165435e1162f37ee39df15d5532b09",
		"inputs": {"enable-aws-auth": false},
		"permissions": {"contents": "read"},
		"secrets": "",
	}],
	"triggers": ["pull_request", "workflow_dispatch"],
	"permissions": {"contents": "read"},
}

# 1. Valid Networking Payload Passes
test_valid_networking_payload_passes if {
	res := consumer.deny with input as valid_networking_payload
	count(res) == 0
}

# 2. Valid Application Payload Passes
test_valid_application_payload_passes if {
	app_payload := json.patch(valid_networking_payload, [
		{"op": "replace", "path": "/consumer_id", "value": "consumer-application"},
		{"op": "replace", "path": "/workload_type", "value": "application"},
		{"op": "replace", "path": "/adapter", "value": "azure"},
		{"op": "replace", "path": "/workflow_calls/0/platform_workflow", "value": "reusable-tf-azure.yml"},
		{"op": "replace", "path": "/workflow_calls/0/inputs", "value": {"enable-azure-auth": false}},
	])
	res := consumer.deny with input as app_payload
	count(res) == 0
}

# 3. Valid Data Platform Payload Passes
test_valid_data_platform_payload_passes if {
	data_payload := json.patch(valid_networking_payload, [
		{"op": "replace", "path": "/consumer_id", "value": "consumer-data-platform"},
		{"op": "replace", "path": "/workload_type", "value": "data-platform"},
		{"op": "replace", "path": "/adapter", "value": "gcp"},
		{"op": "replace", "path": "/workflow_calls/0/platform_workflow", "value": "reusable-tf-gcp.yml"},
		{"op": "replace", "path": "/workflow_calls/0/inputs", "value": {"enable-gcp-auth": false}},
	])
	res := consumer.deny with input as data_payload
	count(res) == 0
}

# 4. Missing or Invalid Version Denied
test_missing_version_denied if {
	bad := json.remove(valid_networking_payload, ["/version"])
	res := consumer.deny with input as bad
	count(res) > 0
}

test_invalid_version_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/version", "value": "2.0"}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 5. Invalid Consumer ID Denied
test_invalid_consumer_id_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/consumer_id", "value": "INVALID_UPPERCASE"}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 6. Unsupported Workload Type Denied
test_unsupported_workload_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/workload_type", "value": "unsupported_workload"}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 7. Unsupported Environment Denied
test_unsupported_environment_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/environment", "value": "production_live"}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 8. Invalid Platform Ref Denied
test_invalid_platform_ref_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/platform_ref", "value": "rogue-org/infraflow"}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 9. Mutable Platform SHA Denied
test_mutable_platform_sha_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/platform_sha", "value": "main"}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 10. Malformed Non-Hex SHA Denied
test_malformed_sha_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/platform_sha", "value": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 11. Absolute Terraform Dir Denied
test_absolute_terraform_dir_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/terraform_dir", "value": "/etc/terraform"}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 12. Path Traversal in Terraform Dir Denied
test_path_traversal_in_terraform_dir_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/terraform_dir", "value": "../../terraform"}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 13. Disabling Mandatory Scanners Denied
test_disabling_mandatory_scanners_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/security_controls/enforce_mandatory_scanners", "value": false}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 14. Deletion Ceiling Exceeding Maximum Denied
test_excessive_deletion_ceiling_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/security_controls/max_allowed_deletions", "value": 50}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 15. Untrusted pull_request_target Trigger Denied
test_pull_request_target_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/triggers", "value": ["pull_request_target"]}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 16. Workflow Root write-all Denied
test_root_write_all_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/permissions", "value": {"_root": "write-all"}}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 17. id-token: write Permission Denied
test_id_token_write_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/permissions", "value": {"id-token": "write", "contents": "read"}}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 18. contents: write Permission Denied
test_contents_write_denied if {
	bad := json.patch(valid_networking_payload, [{"op": "replace", "path": "/permissions", "value": {"contents": "write"}}])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 19. Missing Expected Adapter Workflow Denied
test_missing_expected_adapter_workflow_denied if {
	bad := json.patch(valid_networking_payload, [
		{"op": "replace", "path": "/workflow_calls/0/platform_workflow", "value": "reusable-tf-azure.yml"}
	])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 20. Workflow Platform SHA Mismatch Denied
test_sha_mismatch_denied if {
	bad := json.patch(valid_networking_payload, [
		{"op": "replace", "path": "/workflow_calls/0/platform_sha", "value": "1111111111111111111111111111111111111111"}
	])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 21. Enabling Cloud Auth in Inputs Denied
test_enabling_cloud_auth_denied if {
	bad := json.patch(valid_networking_payload, [
		{"op": "replace", "path": "/workflow_calls/0/inputs/enable-aws-auth", "value": true}
	])
	res := consumer.deny with input as bad
	count(res) > 0
}

# 22. secrets: inherit Denied
test_secrets_inherit_denied if {
	bad := json.patch(valid_networking_payload, [
		{"op": "replace", "path": "/workflow_calls/0/secrets", "value": "inherit"}
	])
	res := consumer.deny with input as bad
	count(res) > 0
}
