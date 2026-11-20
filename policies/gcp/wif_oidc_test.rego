package gcp.wif_oidc_test

import rego.v1
import data.gcp.wif_oidc

# Sample valid provider
valid_provider := {
	"oidc": {
		"issuer_uri": "https://token.actions.githubusercontent.com",
		"allowed_audiences": ["https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/my-pool/providers/my-provider"],
	},
	"attribute_mapping": {
		"google.subject": "assertion.sub",
		"attribute.repository": "assertion.repository",
		"attribute.ref": "assertion.ref",
	},
	"attribute_condition": "assertion.repository == 'TM-threemavithana/infraflow' && assertion.ref == 'refs/heads/main'",
}

# Sample valid service account binding
valid_binding := {
	"role": "roles/iam.workloadIdentityUser",
	"member": "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/my-pool/attribute.repository/TM-threemavithana/infraflow",
}

test_valid_provider_accepted if {
	res := wif_oidc.deny with input as {"provider": valid_provider}
	count(res) == 0
}

test_invalid_issuer_rejected if {
	bad_p := object.union(valid_provider, {
		"oidc": {"issuer_uri": "https://untrusted.issuer.com"},
	})
	res := wif_oidc.deny with input as {"provider": bad_p}
	count(res) > 0
	some r in res
	contains(r, "issuer_uri")
}

test_wildcard_audience_rejected if {
	bad_p := object.union(valid_provider, {
		"oidc": {
			"issuer_uri": "https://token.actions.githubusercontent.com",
			"allowed_audiences": ["*"],
		},
	})
	res := wif_oidc.deny with input as {"provider": bad_p}
	count(res) > 0
	some r in res
	contains(r, "wildcard '*' audience")
}

test_invalid_audience_format_rejected if {
	bad_p := object.union(valid_provider, {
		"oidc": {
			"issuer_uri": "https://token.actions.githubusercontent.com",
			"allowed_audiences": ["https://sts.amazonaws.com"],
		},
	})
	res := wif_oidc.deny with input as {"provider": bad_p}
	count(res) > 0
	some r in res
	contains(r, "invalid; must match provider resource name format")
}

test_missing_subject_mapping_rejected if {
	bad_p := {
		"oidc": valid_provider.oidc,
		"attribute_mapping": {"attribute.repository": "assertion.repository"},
		"attribute_condition": valid_provider.attribute_condition,
	}
	res := wif_oidc.deny with input as {"provider": bad_p}
	count(res) > 0
	some r in res
	contains(r, "must map 'google.subject' to 'assertion.sub'")
}

test_missing_repo_mapping_rejected if {
	bad_p := {
		"oidc": valid_provider.oidc,
		"attribute_mapping": {"google.subject": "assertion.sub"},
		"attribute_condition": valid_provider.attribute_condition,
	}
	res := wif_oidc.deny with input as {"provider": bad_p}
	count(res) > 0
	some r in res
	contains(r, "must map 'attribute.repository' to 'assertion.repository'")
}

test_missing_condition_rejected if {
	bad_p := object.union(valid_provider, {
		"attribute_condition": "",
	})
	res := wif_oidc.deny with input as {"provider": bad_p}
	count(res) > 0
	some r in res
	contains(r, "missing mandatory 'attribute_condition'")
}

test_wildcard_repo_condition_rejected if {
	bad_p := object.union(valid_provider, {
		"attribute_condition": "assertion.repository == '*' && assertion.ref == 'refs/heads/main'",
	})
	res := wif_oidc.deny with input as {"provider": bad_p}
	count(res) > 0
	some r in res
	contains(r, "wildcard '*' repository access")
}

test_untrusted_pull_request_condition_rejected if {
	bad_p := object.union(valid_provider, {
		"attribute_condition": "assertion.repository == 'my-org/my-repo' && assertion.event_name == 'pull_request'",
	})
	res := wif_oidc.deny with input as {"provider": bad_p}
	count(res) > 0
	some r in res
	contains(r, "authorizes untrusted pull_request events")
}

test_missing_scope_condition_rejected if {
	bad_p := object.union(valid_provider, {
		"attribute_condition": "assertion.repository == 'my-org/my-repo'",
	})
	res := wif_oidc.deny with input as {"provider": bad_p}
	count(res) > 0
	some r in res
	contains(r, "must filter on protected branch")
}

test_valid_sa_binding_accepted if {
	res := wif_oidc.deny with input as {"binding": valid_binding}
	count(res) == 0
}

test_wildcard_sa_principal_rejected if {
	bad_b := object.union(valid_binding, {
		"member": "*",
	})
	res := wif_oidc.deny with input as {"binding": bad_b}
	count(res) > 0
	some r in res
	contains(r, "allows wildcard principal")
}

test_invalid_member_format_rejected if {
	bad_b := object.union(valid_binding, {
		"member": "user:attacker@gmail.com",
	})
	res := wif_oidc.deny with input as {"binding": bad_b}
	count(res) > 0
	some r in res
	contains(r, "must begin with 'principalSet://iam.googleapis.com/'")
}

test_wildcard_repo_in_member_rejected if {
	bad_b := object.union(valid_binding, {
		"member": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/attribute.repository/*",
	})
	res := wif_oidc.deny with input as {"binding": bad_b}
	count(res) > 0
	some r in res
	contains(r, "allows wildcard repository access")
}

test_org_wide_repo_owner_in_member_rejected if {
	bad_b := object.union(valid_binding, {
		"member": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/attribute.repository_owner/my-org",
	})
	res := wif_oidc.deny with input as {"binding": bad_b}
	count(res) > 0
	some r in res
	contains(r, "allows organization-wide repository_owner access")
}
