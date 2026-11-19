package common.plan

import rego.v1

# Security-critical control resources that must not be deleted while parent assets remain active
security_control_resources := {
	"aws_s3_bucket_public_access_block",
	"aws_s3_bucket_server_side_encryption_configuration",
	"azurerm_storage_account_network_rules",
	"aws_s3_bucket_policy",
}

# Helper: True only for pure deletions (resource destroyed and NOT replaced)
is_delete_action(change) if {
	change != null
	change.actions == ["delete"]
}

# Helper: True for creates, updates, and replacements (any action that results in an active resource state)
is_active_or_replacement_change(change) if {
	change != null
	change.actions[_] in ["create", "update"]
}

# Helper: True if an attribute is computed / unknown in plan
is_attribute_unknown(change, attr) if {
	change != null
	after_unknown := object.get(change, "after_unknown", {})
	after_unknown != null
	object.get(after_unknown, attr, false) == true
}

# Helper: Module address identity matching
same_module_scope(rc, other) if {
	rc.module_address == other.module_address
}

same_module_scope(rc, other) if {
	not rc.module_address
	not other.module_address
}

# Helper: Detects whether the exact parent asset protected by a standalone security control is also being decommissioned
parent_is_deleted(rc) if {
	rc.type in {"aws_s3_bucket_public_access_block", "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_policy"}
	rc.change != null
	bucket_target := object.get(rc.change.before, "bucket", "")
	bucket_target != ""
	some other in input.resource_changes
	other.type == "aws_s3_bucket"
	same_module_scope(rc, other)
	is_delete_action(other.change)
	s3_parent_matches(other, bucket_target)
}

s3_parent_matches(other, target) if {
	other.change != null
	object.get(other.change.before, "bucket", "") == target
}

s3_parent_matches(other, target) if {
	other.change != null
	object.get(other.change.before, "id", "") == target
}

s3_parent_matches(other, target) if {
	other.change != null
	object.get(other.change.before, "arn", "") == target
}

s3_parent_matches(other, target) if {
	other.name == target
}

parent_is_deleted(rc) if {
	rc.type == "azurerm_storage_account_network_rules"
	rc.change != null
	sa_name := object.get(rc.change.before, "storage_account_name", "")
	sa_name != ""
	some other in input.resource_changes
	other.type == "azurerm_storage_account"
	same_module_scope(rc, other)
	is_delete_action(other.change)
	azure_parent_matches_name(other, sa_name)
}

parent_is_deleted(rc) if {
	rc.type == "azurerm_storage_account_network_rules"
	rc.change != null
	sa_id := object.get(rc.change.before, "storage_account_id", "")
	sa_id != ""
	some other in input.resource_changes
	other.type == "azurerm_storage_account"
	same_module_scope(rc, other)
	is_delete_action(other.change)
	azure_parent_matches_id(other, sa_id)
}

azure_parent_matches_name(other, target) if {
	other.change != null
	object.get(other.change.before, "name", "") == target
}

azure_parent_matches_name(other, target) if {
	other.name == target
}

azure_parent_matches_id(other, target) if {
	other.change != null
	object.get(other.change.before, "id", "") == target
}

# --- Category 1: Incomplete or Errored Plan Inputs ---

deny contains msg if {
	input.format_version
	input.errored == true
	msg := "Plan Violation: Terraform execution plan indicates errors during plan generation"
}

deny contains msg if {
	input.format_version
	not input.resource_changes
	msg := "Plan Violation: Terraform execution plan is missing 'resource_changes' array"
}

deny contains msg if {
	some rc in input.resource_changes
	rc.change == null
	msg := sprintf("Plan Violation: Resource '%v' contains null or missing change block", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	not rc.change
	msg := sprintf("Plan Violation: Resource '%v' contains null or missing change block", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.change != null
	not rc.change.actions
	msg := sprintf("Plan Violation: Resource '%v' contains missing change.actions", [rc.address])
}

# --- Category 2: Security Control Deletions ---

# Deny pure deletion of security-critical controls unless the parent asset is also being decommissioned
deny contains msg if {
	some rc in input.resource_changes
	security_control_resources[rc.type]
	is_delete_action(rc.change)
	not parent_is_deleted(rc)
	msg := sprintf("Plan Violation: Deletion of critical security control '%v' (%v) is prohibited without parent decommissioning", [rc.address, rc.type])
}

# --- Category 3: Active Changes & Replacements (HCL & Plan Violations) ---

# Rule 3.1: Deny planned S3 bucket with public ACL
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	is_active_or_replacement_change(rc.change)
	not is_attribute_unknown(rc.change, "acl")
	rc.change.after.acl in ["public-read", "public-read-write", "website"]
	msg := sprintf("Plan Violation: Resource '%v' specifies public ACL '%v'", [rc.address, rc.change.after.acl])
}

# Rule 3.2: Deny planned S3 bucket if ACL is unknown (computed without explicit secure declaration)
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	is_active_or_replacement_change(rc.change)
	is_attribute_unknown(rc.change, "acl")
	not rc.change.after.acl
	msg := sprintf("Plan Violation: Resource '%v' has unknown/computed ACL. Explicit private ACL must be declared", [rc.address])
}

# Rule 3.3: Deny planned S3 public access block if any protection is disabled or missing
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	is_active_or_replacement_change(rc.change)
	not is_attribute_unknown(rc.change, "block_public_acls")
	object.get(rc.change.after, "block_public_acls", false) != true
	msg := sprintf("Plan Violation: Resource '%v' must set block_public_acls to true", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	is_active_or_replacement_change(rc.change)
	not is_attribute_unknown(rc.change, "block_public_policy")
	object.get(rc.change.after, "block_public_policy", false) != true
	msg := sprintf("Plan Violation: Resource '%v' must set block_public_policy to true", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	is_active_or_replacement_change(rc.change)
	not is_attribute_unknown(rc.change, "ignore_public_acls")
	object.get(rc.change.after, "ignore_public_acls", false) != true
	msg := sprintf("Plan Violation: Resource '%v' must set ignore_public_acls to true", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	is_active_or_replacement_change(rc.change)
	not is_attribute_unknown(rc.change, "restrict_public_buckets")
	object.get(rc.change.after, "restrict_public_buckets", false) != true
	msg := sprintf("Plan Violation: Resource '%v' must set restrict_public_buckets to true", [rc.address])
}

# Rule 3.4: Deny planned S3 public access block with unknown protection attributes
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	is_active_or_replacement_change(rc.change)
	is_attribute_unknown(rc.change, "block_public_acls")
	msg := sprintf("Plan Violation: Resource '%v' has unknown/computed block_public_acls. Explicit true must be declared", [rc.address])
}

# Rule 3.5: Deny planned Azure storage account enabling public blob access
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	is_active_or_replacement_change(rc.change)
	object.get(rc.change.after, "allow_nested_items_to_be_public", false) == true
	msg := sprintf("Plan Violation: Resource '%v' enables public blob access", [rc.address])
}

# Rule 3.6: Deny planned Azure storage account without TLS 1.2
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	is_active_or_replacement_change(rc.change)
	not is_attribute_unknown(rc.change, "min_tls_version")
	object.get(rc.change.after, "min_tls_version", "") != "TLS1_2"
	msg := sprintf("Plan Violation: Resource '%v' min_tls_version must be 'TLS1_2'", [rc.address])
}

# Rule 3.7: Deny planned Azure storage account with unknown TLS version
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_storage_account"
	is_active_or_replacement_change(rc.change)
	is_attribute_unknown(rc.change, "min_tls_version")
	msg := sprintf("Plan Violation: Resource '%v' has unknown min_tls_version. Explicit 'TLS1_2' must be declared", [rc.address])
}

# Rule 3.8: Deny planned GCP storage bucket without uniform bucket-level access
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	is_active_or_replacement_change(rc.change)
	not is_attribute_unknown(rc.change, "uniform_bucket_level_access")
	object.get(rc.change.after, "uniform_bucket_level_access", false) != true
	msg := sprintf("Plan Violation: Resource '%v' must explicitly set uniform_bucket_level_access to true", [rc.address])
}

# Rule 3.9: Deny planned GCP storage bucket with unknown uniform access attribute
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	is_active_or_replacement_change(rc.change)
	is_attribute_unknown(rc.change, "uniform_bucket_level_access")
	msg := sprintf("Plan Violation: Resource '%v' has unknown uniform_bucket_level_access. Explicit true must be declared", [rc.address])
}
