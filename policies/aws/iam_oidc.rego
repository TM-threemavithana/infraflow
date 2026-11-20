package aws.iam_oidc

import rego.v1

# Helper: Extract all policy statements from direct JSON, HCL, or plan inputs
get_statements contains s if {
	some s in input.Statement
}

get_statements contains s if {
	is_object(input.Statement)
	s := input.Statement
}

get_statements contains s if {
	some s in input.statement
}

get_statements contains s if {
	some name
	raw := input.resource.aws_iam_role[name][_].assume_role_policy
	is_string(raw)
	parsed := json.unmarshal(raw)
	some s in parsed.Statement
}

get_statements contains s if {
	some name
	raw := input.resource.aws_iam_role[name][_].assume_role_policy
	is_object(raw)
	some s in raw.Statement
}

# Rule 1: Reject wildcard principal ('*')
deny contains msg if {
	some s in get_statements
	s.Effect == "Allow"
	s.Principal == "*"
	msg := "IAM trust policy statement allows wildcard '*' principal; must specify federated GitHub OIDC provider"
}

deny contains msg if {
	some s in get_statements
	s.Effect == "Allow"
	s.Principal.AWS == "*"
	msg := "IAM trust policy statement allows wildcard AWS principal; must specify federated GitHub OIDC provider"
}

# Helper: Check if statement targets GitHub Actions OIDC
is_github_oidc(s) if {
	fed := s.Principal.Federated
	is_string(fed)
	contains(fed, "token.actions.githubusercontent.com")
}

is_github_oidc(s) if {
	some fed in s.Principal.Federated
	is_string(fed)
	contains(fed, "token.actions.githubusercontent.com")
}

# Helper to retrieve federated principal string
get_federated_principal(s) := fed if {
	is_string(s.Principal.Federated)
	fed := s.Principal.Federated
}

get_federated_principal(s) := fed if {
	some fed in s.Principal.Federated
	is_string(fed)
}

# Rule 2: Validate OIDC Provider ARN format
deny contains msg if {
	some s in get_statements
	s.Effect == "Allow"
	is_github_oidc(s)
	fed := get_federated_principal(s)
	not regex.match(`^arn:aws:iam::[0-9]{12}:oidc-provider/token\.actions\.githubusercontent\.com$`, fed)
	msg := sprintf("Invalid or malformed GitHub OIDC provider ARN '%v'. Must match 'arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com'", [fed])
}

# Helper: Validate that Action is strictly sts:AssumeRoleWithWebIdentity
valid_action(action) if {
	action == "sts:AssumeRoleWithWebIdentity"
}

valid_action(action) if {
	is_array(action)
	count(action) == 1
	action[0] == "sts:AssumeRoleWithWebIdentity"
}

# Rule 3: Enforce Action is strictly sts:AssumeRoleWithWebIdentity
deny contains msg if {
	some s in get_statements
	s.Effect == "Allow"
	is_github_oidc(s)
	not valid_action(s.Action)
	msg := "IAM trust policy statement for GitHub OIDC must strictly authorize only 'sts:AssumeRoleWithWebIdentity'"
}

# Rule 4: Reject statements without a Condition block
deny contains msg if {
	some s in get_statements
	s.Effect == "Allow"
	is_github_oidc(s)
	not s.Condition
	msg := "IAM trust policy statement for GitHub OIDC is missing mandatory 'Condition' block"
}

# Helper: Validate audience condition
has_valid_audience(s) if {
	s.Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
}

# Rule 5: Enforce StringEquals on audience == sts.amazonaws.com
deny contains msg if {
	some s in get_statements
	s.Effect == "Allow"
	is_github_oidc(s)
	s.Condition
	not has_valid_audience(s)
	msg := "IAM trust policy statement must enforce StringEquals: 'token.actions.githubusercontent.com:aud' == 'sts.amazonaws.com'"
}

# Helper: Extract subject conditions from Condition block
extract_condition_sub(cond, op) := res if {
	val := cond[op]["token.actions.githubusercontent.com:sub"]
	is_string(val)
	res := {val}
} else := res if {
	val := cond[op]["token.actions.githubusercontent.com:sub"]
	is_array(val)
	res := {x | some x in val; is_string(x)}
} else := set()

get_subjects(s) := res if {
	res := extract_condition_sub(s.Condition, "StringEquals") | extract_condition_sub(s.Condition, "StringLike")
}

# Rule 6: Reject statements missing subject condition
deny contains msg if {
	some s in get_statements
	s.Effect == "Allow"
	is_github_oidc(s)
	s.Condition
	count(get_subjects(s)) == 0
	msg := "IAM trust policy statement must specify 'token.actions.githubusercontent.com:sub' condition"
}

# Rule 7: Reject unrestricted repository wildcards
deny contains msg if {
	some s in get_statements
	is_github_oidc(s)
	some sub in get_subjects(s)
	sub in {"*", "repo:*", "repo:*:*"}
	msg := sprintf("IAM trust policy subject '%v' contains an unrestricted repository wildcard", [sub])
}

# Rule 8: Reject wildcard organization or wildcard repository access
deny contains msg if {
	some s in get_statements
	is_github_oidc(s)
	some sub in get_subjects(s)
	regex.match(`^repo:\*`, sub)
	msg := sprintf("IAM trust policy subject '%v' permits wildcard organization access", [sub])
}

deny contains msg if {
	some s in get_statements
	is_github_oidc(s)
	some sub in get_subjects(s)
	regex.match(`^repo:[^/:]+/\*:`, sub)
	msg := sprintf("IAM trust policy subject '%v' permits wildcard repository access across an organization", [sub])
}

deny contains msg if {
	some s in get_statements
	is_github_oidc(s)
	some sub in get_subjects(s)
	regex.match(`^repo:[^/:]+@[0-9]+/\*:`, sub)
	msg := sprintf("IAM trust policy subject '%v' permits wildcard repository access across an organization", [sub])
}

deny contains msg if {
	some s in get_statements
	is_github_oidc(s)
	some sub in get_subjects(s)
	regex.match(`^repo:[^/:]+@[0-9]+/\*@[0-9*]+:`, sub)
	msg := sprintf("IAM trust policy subject '%v' permits wildcard repository access across an organization", [sub])
}

# Rule 9: Reject subjects that do not start with 'repo:'
deny contains msg if {
	some s in get_statements
	is_github_oidc(s)
	some sub in get_subjects(s)
	not startswith(sub, "repo:")
	msg := sprintf("IAM trust policy subject '%v' is invalid; must begin with 'repo:<org>/<repo>:'", [sub])
}

# Rule 10: Reject untrusted pull_request subjects for cloud role assumption
deny contains msg if {
	some s in get_statements
	is_github_oidc(s)
	some sub in get_subjects(s)
	contains(sub, ":pull_request")
	msg := sprintf("IAM trust policy subject '%v' permits untrusted pull_request execution; cloud role assumption must be restricted to protected branches or environments", [sub])
}

# Helper: Validate subject scope format (Supports both immutable default OIDC format and legacy format)
# Immutable format (repos created after July 15, 2026): repo:OWNER@OWNER-ID/REPO@REPO-ID:...
is_valid_scope(sub) if {
	regex.match(`^repo:[a-zA-Z0-9_.-]+@[0-9]+/[a-zA-Z0-9_.-]+@[0-9]+:(ref:refs/heads/[a-zA-Z0-9_./*-]+|ref:refs/tags/[a-zA-Z0-9_./*-]+|environment:[a-zA-Z0-9_.-]+)$`, sub)
}

# Legacy format: repo:OWNER/REPO:...
is_valid_scope(sub) if {
	regex.match(`^repo:[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+:(ref:refs/heads/[a-zA-Z0-9_./*-]+|ref:refs/tags/[a-zA-Z0-9_./*-]+|environment:[a-zA-Z0-9_.-]+)$`, sub)
}

# Rule 11: Enforce valid scope (branch, tag, or environment)
deny contains msg if {
	some s in get_statements
	is_github_oidc(s)
	some sub in get_subjects(s)
	not is_valid_scope(sub)
	msg := sprintf("IAM trust policy subject '%v' is overly broad or invalid; must be scoped to ':ref:refs/heads/<branch>', ':ref:refs/tags/<tag>', or ':environment:<env>'", [sub])
}
