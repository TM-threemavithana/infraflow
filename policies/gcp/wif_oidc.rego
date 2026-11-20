package gcp.wif_oidc

import rego.v1

# ==============================================================================
# INFRAFLOW OPA / CONFTEST SECURITY POLICIES:
# Google Cloud Workload Identity Federation (WIF) OIDC Security
#
# Standard: ISO/IEC 27001:2022, NIST SP 800-218 (SSDF), CIS GCP Benchmark v3.0
# Scope: Evaluates Workload Identity Pool Providers & Service Account Bindings
# ==============================================================================

# Helper: Extract all provider resources from input
get_providers contains p if {
	some name
	p := input.resource.google_iam_workload_identity_pool_provider[name][_]
}

get_providers contains p if {
	is_array(input.provider)
	some p in input.provider
	is_object(p.oidc)
}

get_providers contains p if {
	is_object(input.provider)
	is_object(input.provider.oidc)
	p := input.provider
}

get_providers contains p if {
	is_object(input.workload_identity_pool_provider)
	p := input.workload_identity_pool_provider
}

# Helper: Extract all service account IAM bindings/members
get_sa_bindings contains b if {
	some name
	b := input.resource.google_service_account_iam_member[name][_]
}

get_sa_bindings contains b if {
	some name
	b := input.resource.google_service_account_iam_binding[name][_]
}

get_sa_bindings contains b if {
	is_array(input.bindings)
	some b in input.bindings
}

get_sa_bindings contains b if {
	is_object(input.binding)
	b := input.binding
}

# ------------------------------------------------------------------------------
# RULE 1: Enforce GitHub OIDC Issuer URI
# ------------------------------------------------------------------------------
deny contains msg if {
	some p in get_providers
	issuer := object.get(object.get(p, "oidc", {}), "issuer_uri", "")
	issuer != "https://token.actions.githubusercontent.com"
	msg := sprintf("Workload Identity Provider issuer_uri '%v' is invalid; must strictly be 'https://token.actions.githubusercontent.com'", [issuer])
}

# ------------------------------------------------------------------------------
# RULE 2: Validate Allowed Audiences (Reject Wildcards or Disallowed Audiences)
# ------------------------------------------------------------------------------
deny contains msg if {
	some p in get_providers
	audiences := object.get(object.get(p, "oidc", {}), "allowed_audiences", [])
	some aud in audiences
	aud == "*"
	msg := "Workload Identity Provider allows wildcard '*' audience; must specify explicit provider resource URI"
}

deny contains msg if {
	some p in get_providers
	audiences := object.get(object.get(p, "oidc", {}), "allowed_audiences", [])
	some aud in audiences
	aud != ""
	aud != "*"
	not regex.match(`^https://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/`, aud)
	not regex.match(`^//iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/`, aud)
	msg := sprintf("Workload Identity Provider audience '%v' is invalid; must match provider resource name format", [aud])
}

# Helper: Check if attribute mapping contains expected key and value
has_valid_mapping(mappings, key, expected) if {
	mappings[key] == expected
}

# ------------------------------------------------------------------------------
# RULE 3: Mandatory Attribute Mappings (google.subject and attribute.repository)
# ------------------------------------------------------------------------------
deny contains msg if {
	some p in get_providers
	mappings := object.get(p, "attribute_mapping", {})
	not has_valid_mapping(mappings, "google.subject", "assertion.sub")
	msg := "Workload Identity Provider attribute_mapping must map 'google.subject' to 'assertion.sub'"
}

deny contains msg if {
	some p in get_providers
	mappings := object.get(p, "attribute_mapping", {})
	not has_valid_mapping(mappings, "attribute.repository", "assertion.repository")
	msg := "Workload Identity Provider attribute_mapping must map 'attribute.repository' to 'assertion.repository'"
}

# ------------------------------------------------------------------------------
# RULE 4: Attribute Condition Must Be Configured (Reject Unrestricted Access)
# ------------------------------------------------------------------------------
deny contains msg if {
	some p in get_providers
	cond := object.get(p, "attribute_condition", "")
	trim_space(cond) == ""
	msg := "Workload Identity Provider is missing mandatory 'attribute_condition' to restrict token exchange"
}

# ------------------------------------------------------------------------------
# RULE 5: Reject Wildcard Repository Access in Attribute Condition
# ------------------------------------------------------------------------------
deny contains msg if {
	some p in get_providers
	cond := object.get(p, "attribute_condition", "")
	cond != ""
	not contains(cond, "assertion.repository")
	msg := "Workload Identity Provider attribute_condition must explicitly filter on 'assertion.repository'"
}

deny contains msg if {
	some p in get_providers
	cond := object.get(p, "attribute_condition", "")
	regex.match(`assertion\.repository\s*==\s*['"]\*['"]`, cond)
	msg := "Workload Identity Provider attribute_condition allows wildcard '*' repository access"
}

# ------------------------------------------------------------------------------
# RULE 6: Reject Untrusted Pull Request Contexts in Attribute Condition (SEC-02)
# ------------------------------------------------------------------------------
deny contains msg if {
	some p in get_providers
	cond := object.get(p, "attribute_condition", "")
	contains(cond, "pull_request")
	not contains(cond, "!= 'pull_request'")
	not contains(cond, "!= \"pull_request\"")
	msg := "Workload Identity Provider attribute_condition authorizes untrusted pull_request events; cloud authentication must be restricted to protected branches or environments"
}

# ------------------------------------------------------------------------------
# RULE 7: Enforce Protected Branch or Environment Scoping
# ------------------------------------------------------------------------------
has_scope_condition(cond) if {
	contains(cond, "assertion.ref")
}

has_scope_condition(cond) if {
	contains(cond, "assertion.environment")
}

deny contains msg if {
	some p in get_providers
	cond := object.get(p, "attribute_condition", "")
	cond != ""
	not has_scope_condition(cond)
	msg := "Workload Identity Provider attribute_condition must filter on protected branch ('assertion.ref') or environment ('assertion.environment')"
}

# ------------------------------------------------------------------------------
# RULE 8: Reject Wildcard Service Account IAM Principals
# ------------------------------------------------------------------------------
deny contains msg if {
	some b in get_sa_bindings
	b.role == "roles/iam.workloadIdentityUser"
	member := object.get(b, "member", "")
	member in {"*", "allUsers", "allAuthenticatedUsers"}
	msg := "Service account workloadIdentityUser binding allows wildcard principal; must bind to specific principalSet"
}

deny contains msg if {
	some b in get_sa_bindings
	b.role == "roles/iam.workloadIdentityUser"
	some member in object.get(b, "members", [])
	member in {"*", "allUsers", "allAuthenticatedUsers"}
	msg := "Service account workloadIdentityUser binding allows wildcard principal; must bind to specific principalSet"
}

# ------------------------------------------------------------------------------
# RULE 9: Enforce Valid Member Format for WorkloadIdentityUser
# ------------------------------------------------------------------------------
is_valid_wif_member(m) if {
	startswith(m, "principalSet://iam.googleapis.com/")
}

is_valid_wif_member(m) if {
	startswith(m, "principal://iam.googleapis.com/")
}

deny contains msg if {
	some b in get_sa_bindings
	b.role == "roles/iam.workloadIdentityUser"
	member := object.get(b, "member", "")
	member != ""
	not is_valid_wif_member(member)
	msg := sprintf("WorkloadIdentityUser member '%v' is invalid; must begin with 'principalSet://iam.googleapis.com/' or 'principal://iam.googleapis.com/'", [member])
}

deny contains msg if {
	some b in get_sa_bindings
	b.role == "roles/iam.workloadIdentityUser"
	some member in object.get(b, "members", [])
	not is_valid_wif_member(member)
	msg := sprintf("WorkloadIdentityUser member '%v' is invalid; must begin with 'principalSet://iam.googleapis.com/' or 'principal://iam.googleapis.com/'", [member])
}

# ------------------------------------------------------------------------------
# RULE 10: Reject Wildcard Repository in Member Binding
# ------------------------------------------------------------------------------
deny contains msg if {
	some b in get_sa_bindings
	b.role == "roles/iam.workloadIdentityUser"
	member := object.get(b, "member", "")
	regex.match(`/attribute\.repository/[*]`, member)
	msg := sprintf("WorkloadIdentityUser member '%v' allows wildcard repository access", [member])
}

deny contains msg if {
	some b in get_sa_bindings
	b.role == "roles/iam.workloadIdentityUser"
	some member in object.get(b, "members", [])
	regex.match(`/attribute\.repository/[*]`, member)
	msg := sprintf("WorkloadIdentityUser member '%v' allows wildcard repository access", [member])
}

deny contains msg if {
	some b in get_sa_bindings
	b.role == "roles/iam.workloadIdentityUser"
	member := object.get(b, "member", "")
	contains(member, "/attribute.repository_owner/")
	not contains(member, "/attribute.repository/")
	msg := sprintf("WorkloadIdentityUser member '%v' allows organization-wide repository_owner access without exact repository binding", [member])
}
