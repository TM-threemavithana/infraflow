package gcp.storage_backend

import rego.v1

# ==============================================================================
# INFRAFLOW OPA / CONFTEST SECURITY POLICIES:
# Google Cloud Storage (GCS) Terraform State Backend Security
#
# Standards:
# - ISO/IEC 27001:2022 A.8.12 (Data Leakage Prevention)
# - NIST SP 800-218 SSDF PO.3.2 (Secure Software Architecture)
# - CIS Google Cloud Platform Foundation Benchmark v3.0 (Sections 5.1, 5.2)
# Scope: Evaluates GCS Buckets, IAM, ACLs, and Terraform Backend Configurations
# ==============================================================================

# Helper: Extract all GCS bucket definitions
get_buckets contains b if {
	some name
	raw := input.resource.google_storage_bucket[name][_]
	b := object.union(raw, {"_resource_name": name})
}

get_buckets contains b if {
	is_object(input.bucket)
	b := object.union(input.bucket, {"_resource_name": object.get(input.bucket, "name", "bucket")})
}

get_buckets contains b if {
	is_array(input.bucket)
	some raw in input.bucket
	b := object.union(raw, {"_resource_name": object.get(raw, "name", "bucket")})
}

# Helper: Identify state/backend buckets
is_state_bucket(b) if {
	# Checked if explicitly tagged/labeled or named with state/backend
	name := object.get(b, "_resource_name", "")
	regex.match("(?i)(state|backend|tfstate)", name)
}

is_state_bucket(b) if {
	bucket_name := object.get(b, "name", "")
	regex.match("(?i)(state|backend|tfstate)", bucket_name)
}

is_state_bucket(b) if {
	labels := object.get(b, "labels", {})
	some k, v in labels
	regex.match("(?i)(state|backend|tfstate)", sprintf("%v:%v", [k, v]))
}

is_state_bucket(b) if {
	# Explicit flag for direct unit test / backend fixture evaluations
	object.get(b, "is_state_bucket", false) == true
}

is_state_bucket(_) if {
	input.backend.gcs
}

# Helper: Extract versioning enabled
is_versioning_enabled(b) if {
	versioning := object.get(b, "versioning", [])
	is_array(versioning)
	some v in versioning
	object.get(v, "enabled", false) == true
}

is_versioning_enabled(b) if {
	versioning := object.get(b, "versioning", {})
	is_object(versioning)
	object.get(versioning, "enabled", false) == true
}

# ------------------------------------------------------------------------------
# RULE 1: Uniform Bucket-Level Access (CIS GCP 5.2)
# ------------------------------------------------------------------------------
deny contains msg if {
	some b in get_buckets
	is_state_bucket(b)
	object.get(b, "uniform_bucket_level_access", false) != true
	msg := sprintf("GCS state bucket '%v' must explicitly set uniform_bucket_level_access = true", [b._resource_name])
}

# ------------------------------------------------------------------------------
# RULE 2: Public Access Prevention Enforced (CIS GCP 5.1)
# ------------------------------------------------------------------------------
deny contains msg if {
	some b in get_buckets
	is_state_bucket(b)
	pap := object.get(b, "public_access_prevention", "")
	pap != "enforced"
	msg := sprintf("GCS state bucket '%v' must set public_access_prevention = 'enforced' (got '%v')", [b._resource_name, pap])
}

# ------------------------------------------------------------------------------
# RULE 3: Object Versioning Required for State Resilience
# ------------------------------------------------------------------------------
deny contains msg if {
	some b in get_buckets
	is_state_bucket(b)
	not is_versioning_enabled(b)
	msg := sprintf("GCS state bucket '%v' must enable object versioning (versioning.enabled = true)", [b._resource_name])
}

# ------------------------------------------------------------------------------
# RULE 4: Prevent Accidental State Destruction (force_destroy = false)
# ------------------------------------------------------------------------------
deny contains msg if {
	some b in get_buckets
	is_state_bucket(b)
	object.get(b, "force_destroy", false) == true
	msg := sprintf("GCS state bucket '%v' must not set force_destroy = true (prevents catastrophic state loss)", [b._resource_name])
}

# ------------------------------------------------------------------------------
# RULE 5: Customer-Managed Encryption Key (CMEK) Format Validation
# ------------------------------------------------------------------------------
deny contains msg if {
	some b in get_buckets
	is_state_bucket(b)
	encryption := object.get(b, "encryption", [])
	is_array(encryption)
	some enc in encryption
	kms_key := object.get(enc, "default_kms_key_name", "")
	kms_key != ""
	not regex.match(`^projects/[a-z0-9-]+/locations/[a-z0-9-]+/keyRings/[a-zA-Z0-9_-]+/cryptoKeys/[a-zA-Z0-9_-]+$`, kms_key)
	msg := sprintf("GCS state bucket '%v' has invalid KMS key format '%v'", [b._resource_name, kms_key])
}

deny contains msg if {
	some b in get_buckets
	is_state_bucket(b)
	encryption := object.get(b, "encryption", {})
	is_object(encryption)
	kms_key := object.get(encryption, "default_kms_key_name", "")
	kms_key != ""
	not regex.match(`^projects/[a-z0-9-]+/locations/[a-z0-9-]+/keyRings/[a-zA-Z0-9_-]+/cryptoKeys/[a-zA-Z0-9_-]+$`, kms_key)
	msg := sprintf("GCS state bucket '%v' has invalid KMS key format '%v'", [b._resource_name, kms_key])
}

# ------------------------------------------------------------------------------
# RULE 6: Rejection of Public ACLs on GCS Buckets
# ------------------------------------------------------------------------------
disallowed_bucket_acls := {
	"publicRead",
	"publicReadWrite",
	"authenticatedRead",
	"allUsers",
	"allAuthenticatedUsers",
}

deny contains msg if {
	some name
	acl_res := input.resource.google_storage_bucket_acl[name][_]
	some role_entity in object.get(acl_res, "role_entity", [])
	some public_ent in ["allUsers", "allAuthenticatedUsers"]
	contains(role_entity, public_ent)
	msg := sprintf("GCS ACL resource '%v' grants public access to '%v'", [name, public_ent])
}

deny contains msg if {
	some name
	acl_res := input.resource.google_storage_bucket_acl[name][_]
	predefined := object.get(acl_res, "predefined_acl", "")
	disallowed_bucket_acls[predefined]
	msg := sprintf("GCS ACL resource '%v' specifies disallowed public predefined_acl '%v'", [name, predefined])
}

deny contains msg if {
	some name
	acl_res := input.resource.google_storage_default_object_acl[name][_]
	some role_entity in object.get(acl_res, "role_entity", [])
	some public_ent in ["allUsers", "allAuthenticatedUsers"]
	contains(role_entity, public_ent)
	msg := sprintf("GCS default object ACL resource '%v' grants public access to '%v'", [name, public_ent])
}

deny contains msg if {
	some name
	ac_res := input.resource.google_storage_bucket_access_control[name][_]
	entity := object.get(ac_res, "entity", "")
	some public_ent in ["allUsers", "allAuthenticatedUsers"]
	contains(entity, public_ent)
	msg := sprintf("GCS bucket access control resource '%v' grants public access to '%v'", [name, public_ent])
}

# ------------------------------------------------------------------------------
# RULE 7: Rejection of Public IAM Members and Overprivileged Roles
# ------------------------------------------------------------------------------
disallowed_storage_roles := {
	"roles/owner",
	"roles/editor",
}

deny contains msg if {
	some name
	member_res := input.resource.google_storage_bucket_iam_member[name][_]
	member := object.get(member_res, "member", "")
	some public_principal in ["allUsers", "allAuthenticatedUsers"]
	contains(member, public_principal)
	msg := sprintf("GCS IAM member '%v' exposes bucket to public principal '%v'", [name, public_principal])
}

deny contains msg if {
	some name
	member_res := input.resource.google_storage_bucket_iam_member[name][_]
	role := object.get(member_res, "role", "")
	disallowed_storage_roles[role]
	msg := sprintf("GCS IAM member '%v' assigns overprivileged primitive role '%v'; use fine-grained storage roles", [name, role])
}

deny contains msg if {
	some name
	binding_res := input.resource.google_storage_bucket_iam_binding[name][_]
	members := object.get(binding_res, "members", [])
	some member in members
	some public_principal in ["allUsers", "allAuthenticatedUsers"]
	contains(member, public_principal)
	msg := sprintf("GCS IAM binding '%v' exposes bucket to public principal '%v'", [name, public_principal])
}

deny contains msg if {
	some name
	binding_res := input.resource.google_storage_bucket_iam_binding[name][_]
	role := object.get(binding_res, "role", "")
	disallowed_storage_roles[role]
	msg := sprintf("GCS IAM binding '%v' assigns overprivileged primitive role '%v'; use fine-grained storage roles", [name, role])
}

# ------------------------------------------------------------------------------
# RULE 8: Terraform Backend 'gcs' Block Contract Validation
# ------------------------------------------------------------------------------
get_gcs_backends contains backend if {
	backend := input.terraform[_].backend[_].gcs[_]
}

get_gcs_backends contains backend if {
	backend := input.backend.gcs
}

get_gcs_backends contains backend if {
	backend := input.terraform.backend.gcs
}

# Rule 8.1: Bucket name validation
deny contains msg if {
	some backend in get_gcs_backends
	bucket := object.get(backend, "bucket", "")
	bucket == ""
	msg := "Terraform GCS backend configuration must specify a non-empty 'bucket'"
}

deny contains msg if {
	some backend in get_gcs_backends
	bucket := object.get(backend, "bucket", "")
	bucket != ""
	not regex.match(`^[a-z0-9][a-z0-9_.-]{1,61}[a-z0-9]$`, bucket)
	msg := sprintf("Terraform GCS backend bucket '%v' is invalid; must follow Google Cloud Storage bucket naming rules", [bucket])
}

deny contains msg if {
	some backend in get_gcs_backends
	bucket := object.get(backend, "bucket", "")
	some reserved in ["google", "goog"]
	startswith(bucket, reserved)
	msg := sprintf("Terraform GCS backend bucket '%v' must not start with reserved prefix '%v'", [bucket, reserved])
}

# Rule 8.2: Prefix validation
deny contains msg if {
	some backend in get_gcs_backends
	prefix := object.get(backend, "prefix", "")
	prefix == ""
	msg := "Terraform GCS backend prefix must not be empty; must specify a segregated state path"
}

deny contains msg if {
	some backend in get_gcs_backends
	prefix := object.get(backend, "prefix", "")
	startswith(prefix, "/")
	msg := sprintf("Terraform GCS backend prefix '%v' must not start with a leading slash", [prefix])
}

deny contains msg if {
	some backend in get_gcs_backends
	prefix := object.get(backend, "prefix", "")
	contains(prefix, "..")
	msg := sprintf("Terraform GCS backend prefix '%v' must not contain directory traversal '..'", [prefix])
}
