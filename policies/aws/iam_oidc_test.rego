package aws.iam_oidc_test

import rego.v1

import data.aws.iam_oidc

# Helper to construct standard valid statement
valid_statement := {
	"Effect": "Allow",
	"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
	"Action": "sts:AssumeRoleWithWebIdentity",
	"Condition": {
		"StringEquals": {
			"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
			"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
		},
	},
}

test_valid_branch_oidc_policy if {
	policy := {"Version": "2012-10-17", "Statement": [valid_statement]}
	res := iam_oidc.deny with input as policy
	count(res) == 0
}

test_valid_environment_oidc_policy if {
	stmt := object.union(valid_statement, {
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana/infraflow:environment:production",
			},
		},
	})
	policy := {"Version": "2012-10-17", "Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	count(res) == 0
}

test_valid_tag_oidc_policy if {
	stmt := object.union(valid_statement, {
		"Condition": {
			"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
			"StringLike": {"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana/infraflow:ref:refs/tags/v*"},
		},
	})
	policy := {"Version": "2012-10-17", "Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	count(res) == 0
}

test_valid_array_action if {
	stmt := object.union(valid_statement, {"Action": ["sts:AssumeRoleWithWebIdentity"]})
	policy := {"Version": "2012-10-17", "Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	count(res) == 0
}

test_valid_terraform_hcl_iam_role if {
	policy_json := json.marshal({"Version": "2012-10-17", "Statement": [valid_statement]})
	tf_input := {
		"resource": {
			"aws_iam_role": {
				"infraflow_role": [{
					"name": "infraflow-role",
					"assume_role_policy": policy_json,
				}],
			},
		},
	}
	res := iam_oidc.deny with input as tf_input
	count(res) == 0
}

test_reject_wildcard_principal if {
	stmt := object.union(valid_statement, {"Principal": "*"})
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "wildcard '*' principal")
}

test_reject_wildcard_aws_principal if {
	stmt := object.union(valid_statement, {"Principal": {"AWS": "*"}})
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "wildcard AWS principal")
}

test_reject_malformed_oidc_provider_arn if {
	stmt := object.union(valid_statement, {
		"Principal": {"Federated": "arn:aws:iam::12345:oidc-provider/token.actions.githubusercontent.com"},
	})
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "Invalid or malformed GitHub OIDC provider ARN")
}

test_reject_unauthorized_action if {
	stmt := object.union(valid_statement, {"Action": "sts:AssumeRole"})
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "must strictly authorize only 'sts:AssumeRoleWithWebIdentity'")
}

test_reject_multiple_actions_including_unauthorized if {
	stmt := object.union(valid_statement, {"Action": ["sts:AssumeRoleWithWebIdentity", "sts:AssumeRole"]})
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "must strictly authorize only 'sts:AssumeRoleWithWebIdentity'")
}

test_reject_missing_condition_block if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "missing mandatory 'Condition' block")
}

test_reject_missing_audience if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "must enforce StringEquals: 'token.actions.githubusercontent.com:aud' == 'sts.amazonaws.com'")
}

test_reject_invalid_audience if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "api://AzureADTokenExchange",
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana/infraflow:ref:refs/heads/main",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "must enforce StringEquals: 'token.actions.githubusercontent.com:aud' == 'sts.amazonaws.com'")
}

test_reject_missing_subject if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "must specify 'token.actions.githubusercontent.com:sub' condition")
}

test_reject_unrestricted_wildcard_subject if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				"token.actions.githubusercontent.com:sub": "repo:*",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "unrestricted repository wildcard")
}

test_reject_wildcard_org_subject if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
			},
			"StringLike": {
				"token.actions.githubusercontent.com:sub": "repo:*/infraflow:ref:refs/heads/main",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "permits wildcard organization access")
}

test_reject_wildcard_repo_in_org_subject if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
			},
			"StringLike": {
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana/*:ref:refs/heads/main",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "permits wildcard repository access across an organization")
}

test_reject_non_repo_subject if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				"token.actions.githubusercontent.com:sub": "branch:main",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "must begin with 'repo:<org>/<repo>:'")
}

test_reject_pull_request_subject if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana/infraflow:pull_request",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "permits untrusted pull_request execution")
}

test_reject_bare_repo_without_scope if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana/infraflow",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "overly broad or invalid")
}

test_valid_immutable_branch_oidc_policy if {
	stmt := object.union(valid_statement, {
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana@157876462/infraflow@1463731985:ref:refs/heads/main",
			},
		},
	})
	policy := {"Version": "2012-10-17", "Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	count(res) == 0
}

test_valid_immutable_environment_oidc_policy if {
	stmt := object.union(valid_statement, {
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana@157876462/infraflow@1463731985:environment:production",
			},
		},
	})
	policy := {"Version": "2012-10-17", "Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	count(res) == 0
}

test_valid_immutable_tag_oidc_policy if {
	stmt := object.union(valid_statement, {
		"Condition": {
			"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
			"StringLike": {"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana@157876462/infraflow@1463731985:ref:refs/tags/v*"},
		},
	})
	policy := {"Version": "2012-10-17", "Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	count(res) == 0
}

test_reject_immutable_non_numeric_owner_id if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana@abc/infraflow@1463731985:ref:refs/heads/main",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "overly broad or invalid")
}

test_reject_immutable_non_numeric_repo_id if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana@157876462/infraflow@def:ref:refs/heads/main",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "overly broad or invalid")
}

test_reject_immutable_wildcard_repo if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
			},
			"StringLike": {
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana@157876462/*:ref:refs/heads/main",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "permits wildcard repository access across an organization")
}

test_reject_immutable_pull_request if {
	stmt := {
		"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {
				"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				"token.actions.githubusercontent.com:sub": "repo:TM-threemavithana@157876462/infraflow@1463731985:pull_request",
			},
		},
	}
	policy := {"Statement": [stmt]}
	res := iam_oidc.deny with input as policy
	some msg in res
	contains(msg, "permits untrusted pull_request execution")
}
