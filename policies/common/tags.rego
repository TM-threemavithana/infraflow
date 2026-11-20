package common.tags

import rego.v1

valid_environments := {"dev", "staging", "prod", "test"}

# Explicit allowlist of AWS resource types supporting 'tags'
aws_taggable_resources := {
	"aws_s3_bucket",
	"aws_instance",
	"aws_security_group",
	"aws_vpc",
	"aws_subnet",
	"aws_route_table",
	"aws_internet_gateway",
	"aws_nat_gateway",
	"aws_ebs_volume",
	"aws_efs_file_system",
	"aws_dynamodb_table",
	"aws_kms_key",
	"aws_secretsmanager_secret",
	"aws_iam_role",
	"aws_lambda_function",
	"aws_ecs_cluster",
	"aws_ecs_service",
	"aws_sqs_queue",
	"aws_sns_topic",
	"aws_lb",
	"aws_elb",
}

# Explicit allowlist of Azure resource types supporting 'tags'
azure_taggable_resources := {
	"azurerm_storage_account",
	"azurerm_resource_group",
	"azurerm_linux_virtual_machine",
	"azurerm_windows_virtual_machine",
	"azurerm_virtual_machine",
	"azurerm_virtual_network",
	"azurerm_network_security_group",
	"azurerm_network_interface",
	"azurerm_public_ip",
	"azurerm_key_vault",
	"azurerm_managed_disk",
	"azurerm_app_service",
	"azurerm_kubernetes_cluster",
}

# Explicit allowlist of GCP resource types supporting 'labels'
gcp_labelable_resources := {
	"google_storage_bucket",
	"google_compute_instance",
	"google_compute_disk",
	"google_container_cluster",
	"google_bigquery_dataset",
	"google_bigquery_table",
	"google_secret_manager_secret",
	"google_kms_crypto_key",
	"google_pubsub_topic",
}

# Check if resource supports tags (AWS or Azure)
is_taggable(res_type) if {
	aws_taggable_resources[res_type]
}

is_taggable(res_type) if {
	azure_taggable_resources[res_type]
}

# Check if resource supports labels (GCP)
is_labelable(res_type) if {
	gcp_labelable_resources[res_type]
}

# Metadata field lookup helpers supporting title and lowercase conventions
get_env(meta) := val if {
	val := meta.Environment
} else := val if {
	val := meta.environment
}

get_managed_by(meta) := val if {
	val := meta.ManagedBy
} else := val if {
	val := meta.managed_by
} else := val if {
	val := meta.managedby
}

get_project(meta) := val if {
	val := meta.Project
} else := val if {
	val := meta.project
}

# --- Rule 1: Mandatory metadata block existence ---

# Deny AWS/Azure taggable resources that omit the tags block completely
deny contains msg if {
	some res_type, res_name
	is_taggable(res_type)
	res := input.resource[res_type][res_name][_]
	not res.tags
	msg := sprintf("Resource '%v.%v' is missing mandatory 'tags' block", [res_type, res_name])
}

# Deny GCP labelable resources that omit the labels block completely
deny contains msg if {
	some res_type, res_name
	is_labelable(res_type)
	res := input.resource[res_type][res_name][_]
	not res.labels
	msg := sprintf("Resource '%v.%v' is missing mandatory 'labels' block", [res_type, res_name])
}

# --- Rule 2: Mandatory Environment attribute ---

deny contains msg if {
	some res_type, res_name
	is_taggable(res_type)
	res := input.resource[res_type][res_name][_]
	res.tags
	not get_env(res.tags)
	msg := sprintf("Resource '%v.%v' is missing mandatory tag 'Environment'", [res_type, res_name])
}

deny contains msg if {
	some res_type, res_name
	is_labelable(res_type)
	res := input.resource[res_type][res_name][_]
	res.labels
	not get_env(res.labels)
	msg := sprintf("Resource '%v.%v' is missing mandatory label 'Environment'", [res_type, res_name])
}

# --- Rule 3: Mandatory ManagedBy attribute ---

deny contains msg if {
	some res_type, res_name
	is_taggable(res_type)
	res := input.resource[res_type][res_name][_]
	res.tags
	not get_managed_by(res.tags)
	msg := sprintf("Resource '%v.%v' is missing mandatory tag 'ManagedBy'", [res_type, res_name])
}

deny contains msg if {
	some res_type, res_name
	is_labelable(res_type)
	res := input.resource[res_type][res_name][_]
	res.labels
	not get_managed_by(res.labels)
	msg := sprintf("Resource '%v.%v' is missing mandatory label 'ManagedBy'", [res_type, res_name])
}

# --- Rule 4: Mandatory Project attribute ---

deny contains msg if {
	some res_type, res_name
	is_taggable(res_type)
	res := input.resource[res_type][res_name][_]
	res.tags
	not get_project(res.tags)
	msg := sprintf("Resource '%v.%v' is missing mandatory tag 'Project'", [res_type, res_name])
}

deny contains msg if {
	some res_type, res_name
	is_labelable(res_type)
	res := input.resource[res_type][res_name][_]
	res.labels
	not get_project(res.labels)
	msg := sprintf("Resource '%v.%v' is missing mandatory label 'Project'", [res_type, res_name])
}

# --- Rule 5: Environment value validation ---

deny contains msg if {
	some res_type, res_name
	res := input.resource[res_type][res_name][_]
	res.tags
	env := get_env(res.tags)
	env != ""
	not valid_environments[lower(env)]
	msg := sprintf("Resource '%v.%v' has invalid Environment '%v'. Allowed: %v", [res_type, res_name, env, valid_environments])
}

deny contains msg if {
	some res_type, res_name
	res := input.resource[res_type][res_name][_]
	res.labels
	env := get_env(res.labels)
	env != ""
	not valid_environments[lower(env)]
	msg := sprintf("Resource '%v.%v' has invalid Environment '%v'. Allowed: %v", [res_type, res_name, env, valid_environments])
}
