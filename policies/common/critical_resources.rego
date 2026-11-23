package common.critical_resources

import rego.v1

# ==============================================================================
# INFRAFLOW SEMANTIC DESTRUCTION PROTECTION POLICY (Milestone G10.3)
#
# Evaluates Terraform execution plans (tfplan.json) for destructive changes to
# critical enterprise infrastructure across AWS, Azure, and Google Cloud Platform.
#
# Invariants:
# 1. Criticality Over Count: Protects vital assets regardless of total deletion count.
# 2. Complete Asset Coverage: Covers databases, KMS, storage, IAM, and network perimeters.
# 3. Action Differentiation: Classifies direct deletions, destroy-before-create,
#    and create-before-destroy replacements.
# 4. Fail-Closed Malformed Detection: Rejects unknown actions and malformed plan structures.
# 5. Generic Token Rejection: Generic strings ("yes", "confirm", "true") NEVER bypass protection.
# ==============================================================================

# --- Critical Infrastructure Catalogs ---

database_resources := {
	# AWS Databases & Caches
	"aws_db_instance",
	"aws_rds_cluster",
	"aws_rds_cluster_instance",
	"aws_dynamodb_table",
	"aws_elasticache_cluster",
	"aws_elasticache_replication_group",
	"aws_redshift_cluster",
	# Azure Databases & Caches
	"azurerm_postgresql_server",
	"azurerm_postgresql_flexible_server",
	"azurerm_mssql_server",
	"azurerm_mssql_database",
	"azurerm_cosmosdb_account",
	"azurerm_mariadb_server",
	"azurerm_redis_cache",
	# GCP Databases & Caches
	"google_sql_database_instance",
	"google_spanner_instance",
	"google_spanner_database",
	"google_bigtable_instance",
	"google_redis_instance",
}

encryption_resources := {
	# AWS Key Management
	"aws_kms_key",
	"aws_kms_alias",
	"aws_kms_replica_key",
	# Azure Key Vault
	"azurerm_key_vault",
	"azurerm_key_vault_key",
	"azurerm_key_vault_secret",
	"azurerm_key_vault_managed_hardware_security_module",
	# GCP KMS
	"google_kms_crypto_key",
	"google_kms_key_ring",
	"google_kms_crypto_key_version",
}

storage_resources := {
	# AWS Storage Assets
	"aws_s3_bucket",
	# Azure Storage Assets
	"azurerm_storage_account",
	"azurerm_storage_container",
	# GCP Cloud Storage Assets
	"google_storage_bucket",
}

iam_resources := {
	# AWS Identity & Access Management
	"aws_iam_role",
	"aws_iam_policy",
	"aws_iam_role_policy_attachment",
	"aws_iam_user",
	"aws_iam_group",
	"aws_iam_openid_connect_provider",
	# Azure Role Definitions & Assignments
	"azurerm_role_definition",
	"azurerm_role_assignment",
	"azurerm_user_assigned_identity",
	# GCP Service Accounts & IAM Bindings
	"google_service_account",
	"google_project_iam_binding",
	"google_project_iam_member",
	"google_organization_iam_binding",
}

network_security_resources := {
	# AWS Network Security Perimeter
	"aws_security_group",
	"aws_security_group_rule",
	"aws_vpc",
	"aws_route_table",
	"aws_network_acl",
	"aws_internet_gateway",
	# Azure Network Security Perimeter
	"azurerm_network_security_group",
	"azurerm_network_security_rule",
	"azurerm_virtual_network",
	"azurerm_firewall",
	# GCP Compute Network Security Perimeter
	"google_compute_firewall",
	"google_compute_network",
	"google_compute_subnetwork",
	"google_compute_router",
}

# Aggregate union of all critical platform infrastructure
critical_resources := ((((database_resources | encryption_resources) | storage_resources) | iam_resources) | network_security_resources)

# Known canonical Terraform plan action tokens
known_action_tokens := {"no-op", "create", "read", "update", "delete"}

# Generic approval strings strictly prohibited from authorizing critical destructions
generic_confirmation_blocklist := {
	"yes", "y", "true", "1", "destroy", "apply", "confirm", "confirmed",
	"approved", "ok", "proceed", "force", "override", "default",
}


# ==============================================================================
# Helper Functions
# ==============================================================================

# Determines if an action list represents pure deletion
is_pure_delete(actions) if {
	actions == ["delete"]
}

# Determines if an action list represents destroy-before-create replacement
is_destroy_before_create(actions) if {
	actions == ["delete", "create"]
}

# Determines if an action list represents create-before-destroy replacement
is_create_before_destroy(actions) if {
	actions == ["create", "delete"]
}

# Determines if an action list represents any destructive replacement
is_replacement(actions) if {
	is_destroy_before_create(actions)
}

is_replacement(actions) if {
	is_create_before_destroy(actions)
}

# Checks if a valid, plan-specific cryptographic confirmation token is present
is_plan_authorized if {
	auth := input.infraflow_authorization
	auth != null
	auth.authorized == true
	auth.schema_version == "infraflow-destruction-confirmation-v1"
	token := object.get(auth, "token", "")
	token != ""
	not lower(token) in generic_confirmation_blocklist
}


# ==============================================================================
# Policy Evaluation Rules
# ==============================================================================

# --- Category 1: Malformed or Errored Plan Rejection (Fail-Closed) ---

deny contains msg if {
	input.format_version
	input.errored == true
	msg := "Semantic Destruction Violation: Terraform plan indicates errors during plan execution"
}

deny contains msg if {
	input.format_version
	not input.resource_changes
	msg := "Semantic Destruction Violation: Plan JSON is missing 'resource_changes' array"
}

deny contains msg if {
	some rc in input.resource_changes
	rc.change == null
	msg := sprintf("Semantic Destruction Violation: Resource '%v' contains null or missing change block", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	not rc.change
	msg := sprintf("Semantic Destruction Violation: Resource '%v' contains null or missing change block", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.change != null
	not rc.change.actions
	msg := sprintf("Semantic Destruction Violation: Resource '%v' contains missing change.actions", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.change != null
	rc.change.actions != null
	some action in rc.change.actions
	not action in known_action_tokens
	msg := sprintf("Semantic Destruction Violation: Resource '%v' contains unknown or unsupported action token '%v'", [rc.address, action])
}


# --- Category 2: Generic Confirmation Bypass Prevention ---

deny contains msg if {
	input.infraflow_authorization != null
	token := object.get(input.infraflow_authorization, "token", "")
	token != ""
	lower(token) in generic_confirmation_blocklist
	msg := sprintf("Semantic Destruction Violation: Generic confirmation token '%v' is rejected. Plan-specific cryptographic confirmation required.", [token])
}


# --- Category 3: Direct Deletions of Critical Resources ---

deny contains msg if {
	some rc in input.resource_changes
	rc.change != null
	rc.change.actions != null
	critical_resources[rc.type]
	is_pure_delete(rc.change.actions)
	not is_plan_authorized
	msg := sprintf("Semantic Destruction Violation: Direct deletion of critical resource '%v' (type: '%v') is strictly prohibited without plan-specific destruction authorization.", [rc.address, rc.type])
}


# --- Category 4: Destructive Replacements of Critical Resources ---

deny contains msg if {
	some rc in input.resource_changes
	rc.change != null
	rc.change.actions != null
	critical_resources[rc.type]
	is_destroy_before_create(rc.change.actions)
	not is_plan_authorized
	msg := sprintf("Semantic Destruction Violation: Dangerous destroy-before-create replacement of critical resource '%v' (type: '%v') is strictly prohibited without plan-specific destruction authorization.", [rc.address, rc.type])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.change != null
	rc.change.actions != null
	critical_resources[rc.type]
	is_create_before_destroy(rc.change.actions)
	not is_plan_authorized
	msg := sprintf("Semantic Destruction Violation: Create-before-destroy replacement of critical resource '%v' (type: '%v') is strictly prohibited without plan-specific destruction authorization.", [rc.address, rc.type])
}
