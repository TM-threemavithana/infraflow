package azure.entra_oidc_test

import rego.v1
import data.azure.entra_oidc

# 1. Valid Standard Branch Subject Allowed
test_valid_standard_branch_allowed if {
	mock_input := {"resource": {"azurerm_federated_identity_credential": {"valid_branch": [{
		"parent_id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami",
		"resource_group_name": "rg",
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
	}]}}}
	res := entra_oidc.deny with input as mock_input
	count(res) == 0
}

# 2. Valid Standard Environment Subject Allowed
test_valid_standard_environment_allowed if {
	mock_input := {"credentials": [{
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo:TM-threemavithana/infraflow:environment:production",
	}]}
	res := entra_oidc.deny with input as mock_input
	count(res) == 0
}

# 3. Valid Immutable Branch Subject (Post-July 15, 2026 format) Allowed
test_valid_immutable_branch_allowed if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo-id:12345678:ref-type:branch:ref:main",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) == 0
}

# 4. Valid Immutable Environment Subject Allowed
test_valid_immutable_environment_allowed if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo-id:12345678:environment:production",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) == 0
}

# 5. Untrusted Issuer Denied
test_untrusted_issuer_denied if {
	mock_input := {"credential": {
		"issuer": "https://evil-issuer.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo:org/repo:ref:refs/heads/main",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "issuer must strictly be 'https://token.actions.githubusercontent.com'")
}

# 6. Wildcard Audience Denied
test_wildcard_audience_denied if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["*"],
		"subject": "repo:org/repo:ref:refs/heads/main",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must not permit wildcard '*' audience")
}

# 7. Invalid Audience Denied
test_invalid_audience_denied if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://OtherTokenExchange"],
		"subject": "repo:org/repo:ref:refs/heads/main",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must strictly be 'api://AzureADTokenExchange'")
}

# 8. Empty Audience Denied
test_empty_audience_denied if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": [],
		"subject": "repo:org/repo:ref:refs/heads/main",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must specify audience 'api://AzureADTokenExchange'")
}

# 9. Wildcard Subject Denied
test_wildcard_subject_denied if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo:org/*",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "contains forbidden wildcard '*'")
}

# 10. Pull Request Subject Denied (SEC-02)
test_pull_request_subject_denied if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo:org/repo:pull_request",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "targets untrusted pull request event")
}

test_pull_request_ref_denied if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo:org/repo:ref:refs/pull/4/merge",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "targets untrusted pull request event")
}

# 11. Malformed Subject Format Denied
test_malformed_subject_denied if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "user:developer:role:admin",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "format is invalid or unauthorized")
}

# 12. Missing Parent Identity Binding Denied
test_missing_parent_id_denied if {
	mock_input := {"resource": {"azurerm_federated_identity_credential": {"bad_fic": [{
		"parent_id": "",
		"resource_group_name": "rg",
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo:org/repo:ref:refs/heads/main",
	}]}}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must explicitly specify non-empty 'parent_id'")
}

# 13. Invalid UUID Format Denied
test_invalid_uuid_denied if {
	mock_input := {"credential": {
		"tenant_id": "invalid-tenant-guid",
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo:org/repo:ref:refs/heads/main",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "must be a valid RFC 4122 GUID format")
}

# 14. Overprivileged Subscription-Level Role Assignment Denied
test_subscription_owner_role_denied if {
	mock_input := {"resource": {"azurerm_role_assignment": {"bad_role": [{
		"role_definition_name": "Owner",
		"scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
		"principal_id": "00000000-0000-0000-0000-000000000000",
	}]}}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "Overprivileged role 'Owner' granted at subscription scope")
}

test_subscription_contributor_role_denied if {
	mock_input := {"resource": {"azurerm_role_assignment": {"bad_role": [{
		"role_definition_name": "Contributor",
		"scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
		"principal_id": "00000000-0000-0000-0000-000000000000",
	}]}}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "Overprivileged role 'Contributor' granted at subscription scope")
}

# 15. Resource Group Scoped Role Assignment Allowed
test_resource_group_role_allowed if {
	mock_input := {"resource": {"azurerm_role_assignment": {"scoped_role": [{
		"role_definition_name": "Contributor",
		"scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg",
		"principal_id": "00000000-0000-0000-0000-000000000000",
	}]}}}
	res := entra_oidc.deny with input as mock_input
	count(res) == 0
}

# 16. Missing Mandatory Subject Field Denied
test_missing_subject_denied if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "missing mandatory string field 'subject'")
}

# 17. Repository Mismatch Against Expected Repository Denied
test_repository_mismatch_denied if {
	mock_input := {
		"expected_repository": "TM-threemavithana/infraflow",
		"credential": {
			"issuer": "https://token.actions.githubusercontent.com",
			"audiences": ["api://AzureADTokenExchange"],
			"subject": "repo:malicious-org/attacker-repo:ref:refs/heads/main",
		},
	}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "does not match expected repository 'TM-threemavithana/infraflow'")
}

# 18. Repository ID Mismatch Against Expected Repository ID Denied
test_repository_id_mismatch_denied if {
	mock_input := {
		"expected_repository_id": "12345678",
		"credential": {
			"issuer": "https://token.actions.githubusercontent.com",
			"audiences": ["api://AzureADTokenExchange"],
			"subject": "repo-id:99999999:ref-type:branch:ref:main",
		},
	}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "does not match expected repository ID '12345678'")
}

# 19. Missing Slash in repo format Denied
test_missing_repo_slash_denied if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo:singletoken:ref:refs/heads/main",
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "missing repository in 'repo:<org>/<repo>' format")
}

# 20. Flexible Federated Identity Credentials with Custom Claims Denied
test_flexible_fic_claims_denied if {
	mock_input := {"credential": {
		"issuer": "https://token.actions.githubusercontent.com",
		"audiences": ["api://AzureADTokenExchange"],
		"subject": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
		"claims": ["actor", "sub"],
	}}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "Flexible federated identity credentials with custom 'claims' blocks are prohibited")
}

# 21. Tenant ID Mismatch Denied
test_tenant_id_mismatch_denied if {
	mock_input := {
		"expected_tenant_id": "00000000-0000-0000-0000-000000000001",
		"credential": {
			"tenant_id": "00000000-0000-0000-0000-000000000002",
			"issuer": "https://token.actions.githubusercontent.com",
			"audiences": ["api://AzureADTokenExchange"],
			"subject": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
		},
	}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "does not match expected tenant")
}

# 22. Client ID Mismatch Denied
test_client_id_mismatch_denied if {
	mock_input := {
		"expected_client_id": "11111111-1111-1111-1111-111111111111",
		"credential": {
			"client_id": "22222222-2222-2222-2222-222222222222",
			"issuer": "https://token.actions.githubusercontent.com",
			"audiences": ["api://AzureADTokenExchange"],
			"subject": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
		},
	}
	res := entra_oidc.deny with input as mock_input
	count(res) >= 1
	some r in res
	contains(r, "does not match expected client")
}
