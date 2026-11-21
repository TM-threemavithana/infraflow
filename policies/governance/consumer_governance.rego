package governance.consumer

import rego.v1

# ==============================================================================
# InfraFlow Consumer Governance Policy Contract (Milestone G08.3)
# Package: governance.consumer
#
# Evaluates normalized consumer repository metadata, configuration contracts,
# and caller workflow structure against enterprise governance invariants.
# ==============================================================================

# Guard: Exclude Terraform artifacts (HCL ASTs and Plan JSONs) during multi-namespace runs
is_terraform_artifact if {
	input.resource
}

is_terraform_artifact if {
	input.variable
}

is_terraform_artifact if {
	input.output
}

is_terraform_artifact if {
	input.terraform
}

is_terraform_artifact if {
	input.run
}

is_terraform_artifact if {
	input.locals
}

is_terraform_artifact if {
	input.data
}

is_terraform_artifact if {
	input.provider
}

is_terraform_artifact if {
	input.check
}

is_terraform_artifact if {
	input.module
}

is_terraform_artifact if {
	input.resource_changes
}

is_terraform_artifact if {
	input.format_version
}

is_consumer_doc if {
	not is_terraform_artifact
}

# 1. Contract Version Compatibility (Rule 12)
deny contains msg if {
	is_consumer_doc
	not input.version
	msg := "Contract Version: Missing mandatory 'version' attribute."
}

deny contains msg if {
	is_consumer_doc
	input.version
	input.version != "1.0"
	msg := sprintf("Contract Version: Unsupported version '%v'. Expected '1.0'.", [input.version])
}

# 2. Consumer Identity (Rule 1)
deny contains msg if {
	is_consumer_doc
	not input.consumer_id
	msg := "Consumer Identity: Missing mandatory 'consumer_id' attribute."
}

deny contains msg if {
	is_consumer_doc
	input.consumer_id
	not regex.match("^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$", input.consumer_id)
	msg := sprintf("Consumer Identity: Invalid consumer_id '%v'. Must be 3-64 lowercase alphanumeric and hyphens.", [input.consumer_id])
}

# 3. Configured Team & Workload (Rule 2)
supported_workloads := {
	"networking",
	"application",
	"data-platform",
	"general",
	"database",
	"mlops",
	"shared-services",
	"test",
}

deny contains msg if {
	is_consumer_doc
	not input.team
	msg := "Consumer Team: Missing mandatory 'team' attribute."
}

deny contains msg if {
	is_consumer_doc
	input.team
	count(input.team) < 2
	msg := "Consumer Team: Team name must be at least 2 characters."
}

deny contains msg if {
	is_consumer_doc
	input.team
	count(input.team) > 64
	msg := "Consumer Team: Team name cannot exceed 64 characters."
}

deny contains msg if {
	is_consumer_doc
	not input.workload_type
	msg := "Workload Type: Missing mandatory 'workload_type' attribute."
}

deny contains msg if {
	is_consumer_doc
	input.workload_type
	not input.workload_type in supported_workloads
	msg := sprintf("Workload Type: Unsupported workload_type '%v'.", [input.workload_type])
}

# 4. Environment Separation (Rule 10)
supported_environments := {"dev", "staging", "prod", "sand", "test"}

deny contains msg if {
	is_consumer_doc
	not input.environment
	msg := "Environment: Missing mandatory 'environment' attribute."
}

deny contains msg if {
	is_consumer_doc
	input.environment
	not input.environment in supported_environments
	msg := sprintf("Environment: Unsupported environment '%v'.", [input.environment])
}

# 5. Adapter Selection & Platform Compatibility (Rules 3, 13)
supported_adapters := {"aws", "azure", "gcp", "provider-neutral", "generic", "apply-simulation"}

deny contains msg if {
	is_consumer_doc
	not input.adapter
	msg := "Adapter: Missing mandatory 'adapter' attribute."
}

deny contains msg if {
	is_consumer_doc
	input.adapter
	not input.adapter in supported_adapters
	msg := sprintf("Adapter: Unsupported adapter '%v'.", [input.adapter])
}

deny contains msg if {
	is_consumer_doc
	input.platform_ref != "TM-threemavithana/infraflow"
	msg := sprintf("Platform Reference: Invalid platform_ref '%v'. Must be 'TM-threemavithana/infraflow'.", [input.platform_ref])
}

# 6. Immutable Platform SHA Pinning (Rule 5)
mutable_refs := {"main", "master", "latest", "dev", "HEAD", "v0.5.0", "v0.4.0", "v1"}

deny contains msg if {
	is_consumer_doc
	not input.platform_sha
	msg := "Platform Pinning: Missing mandatory 'platform_sha' attribute."
}

deny contains msg if {
	is_consumer_doc
	input.platform_sha in mutable_refs
	msg := sprintf("Platform Pinning: Mutable reference '%v' rejected. Must pin an immutable 40-character hexadecimal commit SHA.", [input.platform_sha])
}

deny contains msg if {
	is_consumer_doc
	input.platform_sha
	not input.platform_sha in mutable_refs
	not regex.match("^[0-9a-f]{40}$", input.platform_sha)
	msg := sprintf("Platform Pinning: Invalid commit SHA '%v'. Must be exactly 40 lowercase hexadecimal characters.", [input.platform_sha])
}

# 7. Terraform Directory Path Containment (Rule 11)
deny contains msg if {
	is_consumer_doc
	not input.terraform_dir
	msg := "Terraform Directory: Missing mandatory 'terraform_dir' attribute."
}

deny contains msg if {
	is_consumer_doc
	input.terraform_dir
	startswith(input.terraform_dir, "/")
	msg := sprintf("Terraform Directory: Absolute path '%v' rejected.", [input.terraform_dir])
}

deny contains msg if {
	is_consumer_doc
	input.terraform_dir
	startswith(input.terraform_dir, "~")
	msg := sprintf("Terraform Directory: Tilde path '%v' rejected.", [input.terraform_dir])
}

deny contains msg if {
	is_consumer_doc
	input.terraform_dir
	regex.match("(^|[\\\\/])\\.\\.([\\\\/]|$)", input.terraform_dir)
	msg := sprintf("Terraform Directory: Path traversal ('..') in '%v' rejected.", [input.terraform_dir])
}

# 8. Mandatory Security Scanners & Destructive Controls (Rules 6, 14)
deny contains msg if {
	is_consumer_doc
	not input.security_controls.enforce_mandatory_scanners
	msg := "Mandatory Scanners: enforce_mandatory_scanners must be strictly true."
}

deny contains msg if {
	is_consumer_doc
	input.security_controls.max_allowed_deletions < 0
	msg := "Deletion Ceiling: max_allowed_deletions cannot be negative."
}

deny contains msg if {
	is_consumer_doc
	input.security_controls.max_allowed_deletions > 25
	msg := "Deletion Ceiling: max_allowed_deletions cannot exceed 25."
}

# 9. Untrusted PR Trigger Restrictions (Rule 8)
deny contains msg if {
	is_consumer_doc
	"pull_request_target" in input.triggers
	msg := "Trigger Safety: 'pull_request_target' trigger is strictly forbidden due to privilege escalation risks."
}

# 10. Least-Privilege Permissions (Rule 7)
deny contains msg if {
	is_consumer_doc
	input.permissions._root == "write-all"
	msg := "Permissions: Workflow-level 'write-all' is strictly forbidden."
}

deny contains msg if {
	is_consumer_doc
	input.permissions["id-token"] == "write"
	msg := "Permissions: 'id-token: write' is strictly forbidden in cloud-free consumer workflows."
}

deny contains msg if {
	is_consumer_doc
	some perm, val in input.permissions
	perm != "_root"
	val in {"write", "write-all"}
	msg := sprintf("Permissions: Excessive permission '%v: %v' detected. Must be read-only.", [perm, val])
}

# 11. Required Adapter Workflow Invocation (Rule 4)
adapter_workflow_map := {
	"aws": "reusable-tf-aws.yml",
	"azure": "reusable-tf-azure.yml",
	"gcp": "reusable-tf-gcp.yml",
	"provider-neutral": "reusable-tf-validate.yml",
	"generic": "reusable-tf-validate.yml",
	"apply-simulation": "reusable-tf-apply.yml",
}

deny contains msg if {
	is_consumer_doc
	input.adapter
	expected_wf := adapter_workflow_map[input.adapter]
	called_wfs := {call.platform_workflow | some call in input.workflow_calls}
	not expected_wf in called_wfs
	msg := sprintf("Adapter Invocation: Config specifies adapter '%v' (requires '%v'), but workflow calls: %v.", [input.adapter, expected_wf, called_wfs])
}

# 12. Workflow Reference Platform SHA Match (Rule 5)
deny contains msg if {
	is_consumer_doc
	some call in input.workflow_calls
	call.platform_sha != input.platform_sha
	msg := sprintf("Platform SHA Mismatch: Workflow calls '%v' with SHA '%v', but config specifies '%v'.", [call.platform_workflow, call.platform_sha, input.platform_sha])
}

# 13. Cloud-Free Authentication Restrictions (Rule 9)
disallowed_auth_keys := {"enable-aws-auth", "enable-azure-auth", "enable-gcp-auth", "enable_aws_auth", "enable_azure_auth", "enable_gcp_auth"}

deny contains msg if {
	is_consumer_doc
	some call in input.workflow_calls
	some key in disallowed_auth_keys
	object.get(call.inputs, key, false) == true
	msg := sprintf("Cloud Auth Safety: Reusable workflow call '%v' passes '%v: true'. Live cloud authentication is forbidden.", [call.platform_workflow, key])
}

# 14. Secret Inheritance Rejection (Rule 15)
deny contains msg if {
	is_consumer_doc
	some call in input.workflow_calls
	call.secrets == "inherit"
	msg := sprintf("Secret Safety: Workflow call '%v' specifies 'secrets: inherit'. Secret inheritance is strictly forbidden.", [call.platform_workflow])
}
