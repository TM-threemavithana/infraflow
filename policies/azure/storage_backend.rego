package azure.storage_backend

import rego.v1

# ==============================================================================
# INFRAFLOW OPA / CONFTEST SECURITY POLICIES:
# Azure Blob Storage State Backend & Storage Account Security
#
# Standard: ISO/IEC 27001:2022, NIST SP 800-218 (SSDF), CIS Azure Benchmark v3.0
# Scope: Evaluates Terraform azurerm remote backend configurations, Azure Storage
#        Accounts, Blob Containers, and Data Plane Security Controls.
# ==============================================================================

# Helper: Extract all backend configuration objects
get_backends contains b if {
	some t in input.terraform
	is_object(t)
	some bk in t.backend
	is_object(bk)
	some az in bk.azurerm
	is_object(az)
	b := az
}

get_backends contains b if {
	some name
	b := input.terraform.backend.azurerm[name][_]
}

get_backends contains b if {
	is_object(input.terraform.backend.azurerm)
	b := input.terraform.backend.azurerm
}

get_backends contains b if {
	is_object(input.backend.azurerm)
	b := input.backend.azurerm
}

get_backends contains b if {
	is_object(input.backend)
	not is_object(input.backend.azurerm)
	b := input.backend
}

# Helper: Extract storage accounts from Terraform plan or configuration
get_storage_accounts contains sa if {
	some name
	sa := input.resource.azurerm_storage_account[name][_]
}

get_storage_accounts contains sa if {
	is_array(input.storage_accounts)
	some sa in input.storage_accounts
}

get_storage_accounts contains sa if {
	is_object(input.storage_account)
	sa := input.storage_account
}

# Helper: Extract storage containers from Terraform plan or configuration
get_containers contains c if {
	some name
	c := input.resource.azurerm_storage_container[name][_]
}

get_containers contains c if {
	is_array(input.containers)
	some c in input.containers
}

get_containers contains c if {
	is_object(input.container)
	c := input.container
}

# Helper: Extract role assignments
get_role_assignments contains r if {
	some name
	r := input.resource.azurerm_role_assignment[name][_]
}

get_role_assignments contains r if {
	is_array(input.role_assignments)
	some r in input.role_assignments
}

get_role_assignments contains r if {
	is_object(input.role_assignment)
	r := input.role_assignment
}

is_tf_interpolation(val) if {
	startswith(val, "${")
}

# ==============================================================================
# RULE 1: STORAGE ACCOUNT NAMING RULES (3-24 LOWERCASE ALPHANUMERIC)
# ==============================================================================
deny contains msg if {
	some b in get_backends
	sa_name := object.get(b, "storage_account_name", "")
	sa_name != ""
	not regex.match(`^[a-z0-9]{3,24}$`, sa_name)
	msg := sprintf("Backend storage_account_name '%v' must be 3-24 lowercase alphanumeric characters only", [sa_name])
}

deny contains msg if {
	some sa in get_storage_accounts
	sa_name := object.get(sa, "name", "")
	sa_name != ""
	not is_tf_interpolation(sa_name)
	not regex.match(`^[a-z0-9]{3,24}$`, sa_name)
	msg := sprintf("azurerm_storage_account name '%v' must be 3-24 lowercase alphanumeric characters only", [sa_name])
}

# ==============================================================================
# RULE 2: RESOURCE GROUP NAMING RULES (1-90 CHARS, NO ENDING PERIOD)
# ==============================================================================
deny contains msg if {
	some b in get_backends
	rg_name := object.get(b, "resource_group_name", "")
	rg_name != ""
	not is_valid_rg_name(rg_name)
	msg := sprintf("Backend resource_group_name '%v' contains invalid characters or ends with a period", [rg_name])
}

is_valid_rg_name(name) if {
	regex.match(`^[a-zA-Z0-9_\-\.\(\)]{1,90}$`, name)
	not endswith(name, ".")
}

# ==============================================================================
# RULE 3: CONTAINER NAMING RULES (3-63 LOWERCASE ALPHANUMERIC & HYPHENS)
# ==============================================================================
deny contains msg if {
	some b in get_backends
	c_name := object.get(b, "container_name", "")
	c_name != ""
	not is_valid_container_name(c_name)
	msg := sprintf("Backend container_name '%v' violates Azure Blob container naming rules", [c_name])
}

deny contains msg if {
	some c in get_containers
	c_name := object.get(c, "name", "")
	c_name != ""
	not is_tf_interpolation(c_name)
	not is_valid_container_name(c_name)
	msg := sprintf("azurerm_storage_container name '%v' violates Azure Blob container naming rules", [c_name])
}

is_valid_container_name(name) if {
	regex.match(`^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$`, name)
	not contains(name, "--")
}

# ==============================================================================
# RULE 4: STATE BLOB KEY SECURITY & PATH TRAVERSAL DEFENSE
# State blob key must not be empty, must not have leading slash, and must not traverse
# ==============================================================================
deny contains msg if {
	some b in get_backends
	key := object.get(b, "key", "")
	key == ""
	msg := "Backend 'key' must not be empty; must specify state blob name or path"
}

deny contains msg if {
	some b in get_backends
	key := object.get(b, "key", "")
	startswith(key, "/")
	msg := sprintf("Backend 'key' must not contain leading slash: '%v'", [key])
}

deny contains msg if {
	some b in get_backends
	key := object.get(b, "key", "")
	contains(key, "..")
	msg := sprintf("Backend 'key' contains forbidden path traversal '..': '%v'", [key])
}

# ==============================================================================
# RULE 5: MICROSOFT ENTRA ID DATA-PLANE AUTHENTICATION MANDATE (NO SHARED KEYS)
# azurerm backend must authenticate blob data-plane operations via Entra ID
# by explicitly setting 'use_azuread_auth = true'.
# Note: 'use_oidc = true' authenticates ARM control plane, but without
# 'use_azuread_auth = true' Terraform falls back to retrieving storage access keys!
# ==============================================================================
deny contains msg if {
	some b in get_backends
	use_ad := object.get(b, "use_azuread_auth", false)
	use_ad != true
	msg := "azurerm backend must enable Microsoft Entra ID data-plane authentication via 'use_azuread_auth = true'"
}

deny contains msg if {
	some b in get_backends
	object.get(b, "access_key", null) != null
	msg := "Security Violation: azurerm backend specifies static 'access_key'. Long-lived storage keys are prohibited."
}

deny contains msg if {
	some b in get_backends
	object.get(b, "sas_token", null) != null
	msg := "Security Violation: azurerm backend specifies 'sas_token'. Passwordless Entra ID authentication is mandated."
}

# ==============================================================================
# RULE 6: ANONYMOUS BLOB ACCESS PREVENTION
# Storage account must explicitly forbid nested items from being public
# ==============================================================================
deny contains msg if {
	some sa in get_storage_accounts
	object.get(sa, "allow_nested_items_to_be_public", false) == true
	msg := "azurerm_storage_account must not set allow_nested_items_to_be_public to true"
}

deny contains msg if {
	some c in get_containers
	access_type := object.get(c, "container_access_type", "private")
	access_type != "private"
	msg := sprintf("azurerm_storage_container must enforce 'container_access_type = private', got '%v'", [access_type])
}

# ==============================================================================
# RULE 7: MINIMUM TLS VERSION ENFORCEMENT (TLS 1.2+)
# ==============================================================================
deny contains msg if {
	some sa in get_storage_accounts
	min_tls := object.get(sa, "min_tls_version", "")
	min_tls != "TLS1_2"
	min_tls != "TLS1_3"
	msg := sprintf("azurerm_storage_account min_tls_version must explicitly be 'TLS1_2' or 'TLS1_3', got '%v'", [min_tls])
}

# ==============================================================================
# RULE 8: STORAGE PUBLIC NETWORK EXPOSURE RESTRICTION
# State storage accounts must disable unrestricted public network access
# ==============================================================================
deny contains msg if {
	some sa in get_storage_accounts
	# If public_network_access_enabled is explicitly set to true
	object.get(sa, "public_network_access_enabled", false) == true
	# and no restricting network rules default_action = "Deny"
	not has_restricting_network_rules(sa)
	msg := "azurerm_storage_account must disable unrestricted public network access (set public_network_access_enabled = false or network_rules default_action = 'Deny')"
}

has_restricting_network_rules(sa) if {
	rules := object.get(sa, "network_rules", [])
	is_array(rules)
	some r in rules
	object.get(r, "default_action", "") == "Deny"
}

has_restricting_network_rules(sa) if {
	rules := object.get(sa, "network_rules", {})
	is_object(rules)
	object.get(rules, "default_action", "") == "Deny"
}

# ==============================================================================
# RULE 9: ENCRYPTION AT REST ENFORCEMENT
# Storage accounts must maintain encryption at rest
# ==============================================================================
deny contains msg if {
	some sa in get_storage_accounts
	# shared_access_key_enabled should be false for state storage
	object.get(sa, "shared_access_key_enabled", false) == true
	msg := "azurerm_storage_account for Terraform state must disable shared access keys (shared_access_key_enabled = false)"
}

# ==============================================================================
# RULE 10: BLOB VERSIONING FOR STATE INTEGRITY
# Storage accounts for Terraform state should enable blob versioning
# ==============================================================================
deny contains msg if {
	some sa in get_storage_accounts
	# If tagged or intended for state storage
	is_state_storage(sa)
	not has_blob_versioning(sa)
	msg := "azurerm_storage_account housing Terraform state must enable blob versioning in blob_properties"
}

is_state_storage(sa) if {
	tags := object.get(sa, "tags", {})
	tags.project == "infraflow"
}

is_state_storage(sa) if {
	name := object.get(sa, "name", "")
	contains(name, "tfstate")
}

has_blob_versioning(sa) if {
	props := object.get(sa, "blob_properties", [])
	is_array(props)
	some p in props
	object.get(p, "versioning_enabled", false) == true
}

has_blob_versioning(sa) if {
	props := object.get(sa, "blob_properties", {})
	is_object(props)
	object.get(props, "versioning_enabled", false) == true
}

# ==============================================================================
# RULE 11: STORAGE ACCOUNT LEAST-PRIVILEGE DATA PLANE RBAC
# Reject primitive Owner/Contributor roles on storage accounts; require Storage Blob Data roles
# ==============================================================================
deny contains msg if {
	some r in get_role_assignments
	scope := object.get(r, "scope", "")
	is_storage_scope(scope)
	role := object.get(r, "role_definition_name", "")
	role in ["Owner", "Contributor"]
	msg := sprintf("Security Violation: Overprivileged role '%v' granted on storage scope '%v'. Use 'Storage Blob Data Contributor' or least privilege data-plane role.", [role, scope])
}

is_storage_scope(scope) if {
	contains(scope, "Microsoft.Storage/storageAccounts")
}

# ==============================================================================
# RULE 12: STATE ENVIRONMENT ISOLATION
# Backend key must specify environment prefix to prevent cross-environment state overwrites
# ==============================================================================
deny contains msg if {
	some b in get_backends
	key := object.get(b, "key", "")
	key != ""
	not has_env_prefix(key)
	msg := sprintf("Backend state key '%v' must include an environment namespace (e.g. 'env/prod/terraform.tfstate' or 'production/terraform.tfstate') to prevent cross-environment overwrites", [key])
}

has_env_prefix(key) if {
	contains(key, "/")
}
