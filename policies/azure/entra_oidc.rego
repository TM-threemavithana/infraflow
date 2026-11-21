package azure.entra_oidc

import rego.v1

# ==============================================================================
# INFRAFLOW OPA / CONFTEST SECURITY POLICIES:
# Microsoft Entra ID Workload Identity Federation (OIDC) Security
#
# Standard: ISO/IEC 27001:2022, NIST SP 800-218 (SSDF), CIS Azure Benchmark v3.0
# Scope: Evaluates Microsoft Entra ID Federated Identity Credentials (FIC) and
#        User-Assigned Managed Identity OIDC Trust Configurations.
# ==============================================================================

# Helper: Extract all federated identity credential objects from Terraform resources or direct inputs
get_credentials contains c if {
	some name
	c := input.resource.azuread_application_federated_identity_credential[name][_]
}

get_credentials contains c if {
	some name
	c := input.resource.azurerm_federated_identity_credential[name][_]
}

get_credentials contains c if {
	is_array(input.credentials)
	some c in input.credentials
}

get_credentials contains c if {
	is_object(input.credential)
	c := input.credential
}

get_credentials contains c if {
	is_object(input.federated_identity_credential)
	c := input.federated_identity_credential
}

get_credentials contains c if {
	# Root-level credential format
	is_string(object.get(input, "issuer", null))
	c := input
}

# Helper: Extract audiences regardless of whether modeled as array or string or 'audience' vs 'audiences'
get_audiences(c) := auds if {
	is_array(object.get(c, "audiences", null))
	auds := c.audiences
}

get_audiences(c) := [c.audiences] if {
	is_string(object.get(c, "audiences", null))
}

get_audiences(c) := auds if {
	is_array(object.get(c, "audience", null))
	auds := c.audience
}

get_audiences(c) := [c.audience] if {
	is_string(object.get(c, "audience", null))
}

get_audiences(c) := [] if {
	not is_array(object.get(c, "audiences", null))
	not is_string(object.get(c, "audiences", null))
	not is_array(object.get(c, "audience", null))
	not is_string(object.get(c, "audience", null))
}

# Helper: Extract all Azure role assignments
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

# ==============================================================================
# RULE 1: STRICT ISSUER VALIDATION
# Must strictly match the official GitHub Actions token issuer
# ==============================================================================
deny contains msg if {
	some c in get_credentials
	issuer := object.get(c, "issuer", "")
	issuer != "https://token.actions.githubusercontent.com"
	msg := sprintf("Federated credential issuer must strictly be 'https://token.actions.githubusercontent.com', got '%v'", [issuer])
}

# ==============================================================================
# RULE 2: STRICT AUDIENCE VALIDATION
# Azure Public Cloud token exchange strictly mandates 'api://AzureADTokenExchange'
# ==============================================================================
deny contains msg if {
	some c in get_credentials
	auds := get_audiences(c)
	count(auds) == 0
	msg := "Federated credential must specify audience 'api://AzureADTokenExchange'"
}

deny contains msg if {
	some c in get_credentials
	some aud in get_audiences(c)
	aud == "*"
	msg := "Federated credential must not permit wildcard '*' audience; must strictly be 'api://AzureADTokenExchange'"
}

deny contains msg if {
	some c in get_credentials
	some aud in get_audiences(c)
	aud != "api://AzureADTokenExchange"
	msg := sprintf("Federated credential audience must strictly be 'api://AzureADTokenExchange', got '%v'", [aud])
}

# ==============================================================================
# RULE 3: WILDCARD SUBJECT REJECTION (NO BROAD TRUST Broadening)
# Entra ID standard Federated Identity Credentials enforce exact string matching.
# Wildcards ('*') are strictly rejected.
# ==============================================================================
deny contains msg if {
	some c in get_credentials
	subj := object.get(c, "subject", "")
	contains(subj, "*")
	msg := sprintf("Federated credential subject contains forbidden wildcard '*': '%v'. Standard Entra ID requires exact subject match.", [subj])
}

# ==============================================================================
# RULE 4: UNTRUSTED PULL REQUEST REJECTION (SEC-02 FAIL-CLOSED)
# Untrusted pull requests must never be granted federated cloud tokens
# ==============================================================================
deny contains msg if {
	some c in get_credentials
	subj := object.get(c, "subject", "")
	is_pull_request_subject(subj)
	msg := sprintf("Federated credential subject targets untrusted pull request event: '%v'. Pull requests cannot request cloud credentials (SEC-02).", [subj])
}

is_pull_request_subject(subj) if {
	contains(subj, ":pull_request")
}

is_pull_request_subject(subj) if {
	contains(subj, ":ref:refs/pull/")
}

is_pull_request_subject(subj) if {
	contains(subj, ":ref-type:pull_request")
}

# ==============================================================================
# RULE 5: EXACT TRUSTED FEDERATED SUBJECT FORMAT VALIDATION
# Subject must strictly match either:
# 1. Standard branch format: repo:<org>/<repo>:ref:refs/heads/<branch>
# 2. Standard tag format:    repo:<org>/<repo>:ref:refs/tags/<tag>
# 3. Standard environment:   repo:<org>/<repo>:environment:<env>
# 4. Immutable GitHub format (post-July 15, 2026):
#    repo-id:<id>:ref-type:branch:ref:<branch>
#    repo-id:<id>:ref-type:tag:ref:<tag>
#    repo-id:<id>:environment:<env>
# ==============================================================================
deny contains msg if {
	some c in get_credentials
	subj := object.get(c, "subject", "")
	not is_valid_subject_format(subj)
	msg := sprintf("Federated credential subject format is invalid or unauthorized: '%v'", [subj])
}

is_valid_subject_format(subj) if {
	regex.match(`^repo:[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+:ref:refs/heads/[a-zA-Z0-9_./-]+$`, subj)
}

is_valid_subject_format(subj) if {
	regex.match(`^repo:[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+:ref:refs/tags/[a-zA-Z0-9_./-]+$`, subj)
}

is_valid_subject_format(subj) if {
	regex.match(`^repo:[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+:environment:[a-zA-Z0-9_.-]+$`, subj)
}

is_valid_subject_format(subj) if {
	# Immutable post-July 15, 2026 format for branches
	regex.match(`^repo-id:[0-9]+:ref-type:branch:ref:[a-zA-Z0-9_./-]+$`, subj)
}

is_valid_subject_format(subj) if {
	# Immutable post-July 15, 2026 format for tags
	regex.match(`^repo-id:[0-9]+:ref-type:tag:ref:[a-zA-Z0-9_./-]+$`, subj)
}

is_valid_subject_format(subj) if {
	# Immutable post-July 15, 2026 format for environments
	regex.match(`^repo-id:[0-9]+:environment:[a-zA-Z0-9_.-]+$`, subj)
}

# ==============================================================================
# RULE 6: REPOSITORY AND ORGANIZATION BOUNDARY ENFORCEMENT
# Subject must specify non-empty repository and organization
# ==============================================================================
deny contains msg if {
	some c in get_credentials
	subj := object.get(c, "subject", "")
	startswith(subj, "repo:/")
	msg := sprintf("Federated credential subject missing organization boundary: '%v'", [subj])
}

deny contains msg if {
	some c in get_credentials
	subj := object.get(c, "subject", "")
	startswith(subj, "repo-id::")
	msg := sprintf("Federated credential subject missing numeric repository ID: '%v'", [subj])
}

# ==============================================================================
# RULE 7: MANDATORY MANAGED IDENTITY PARENT BINDING
# Reject arbitrary managed identity substitution
# ==============================================================================
deny contains msg if {
	some c in get_credentials
	# If resource is azurerm_federated_identity_credential, parent_id must not be empty
	object.get(c, "resource_group_name", null) != null
	parent := object.get(c, "parent_id", "")
	parent == ""
	msg := "azurerm_federated_identity_credential must explicitly specify non-empty 'parent_id' User-Assigned Identity binding"
}

deny contains msg if {
	some c in get_credentials
	# If resource is azuread_application_federated_identity_credential, application_id must not be empty
	object.get(c, "display_name", null) != null
	app_id := object.get(c, "application_id", object.get(c, "application_object_id", ""))
	app_id == ""
	msg := "azuread_application_federated_identity_credential must specify non-empty 'application_id'"
}

# ==============================================================================
# RULE 8: AZURE IDENTITY UUID FORMAT CONSTRAINTS
# Any tenant_id or client_id declared in credential or binding must be a valid UUID
# ==============================================================================
deny contains msg if {
	some c in get_credentials
	some field in ["tenant_id", "client_id"]
	val := object.get(c, field, null)
	is_string(val)
	val != ""
	not regex.match(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`, val)
	msg := sprintf("Azure '%v' must be a valid UUID format: '%v'", [field, val])
}

# ==============================================================================
# RULE 9: LEAST-PRIVILEGE AZURE RBAC ENFORCEMENT
# Reject subscription-level Owner or Contributor role assignments
# ==============================================================================
deny contains msg if {
	some r in get_role_assignments
	role_name := object.get(r, "role_definition_name", "")
	role_name in ["Owner", "Contributor"]
	scope := object.get(r, "scope", "")
	is_subscription_scope(scope)
	msg := sprintf("Security Violation: Overprivileged role '%v' granted at subscription scope '%v'. Roles must be scoped to resource group or resource.", [role_name, scope])
}

is_subscription_scope(scope) if {
	regex.match(`^/subscriptions/[0-9a-fA-F-]{36}$`, scope)
}

# ==============================================================================
# RULE 10: FAIL-CLOSED ON MALFORMED FEDERATION CONFIGURATION
# Reject configurations missing essential security fields
# ==============================================================================
deny contains msg if {
	some c in get_credentials
	not is_string(object.get(c, "subject", null))
	msg := "Federated credential missing mandatory string field 'subject'"
}

deny contains msg if {
	some c in get_credentials
	not is_string(object.get(c, "issuer", null))
	msg := "Federated credential missing mandatory string field 'issuer'"
}
