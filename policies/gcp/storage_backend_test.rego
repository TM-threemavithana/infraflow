package gcp.storage_backend_test

import rego.v1
import data.gcp.storage_backend

# ------------------------------------------------------------------------------
# Test Fixtures
# ------------------------------------------------------------------------------
valid_state_bucket := {
	"name": "my-org-tfstate-bucket",
	"uniform_bucket_level_access": true,
	"public_access_prevention": "enforced",
	"versioning": [{"enabled": true}],
	"force_destroy": false,
	"encryption": [{
		"default_kms_key_name": "projects/my-project/locations/us-central1/keyRings/tf-ring/cryptoKeys/tf-key",
	}],
}

# ------------------------------------------------------------------------------
# Unit Tests: Bucket Resource Rules
# ------------------------------------------------------------------------------
test_valid_state_bucket_accepted if {
	res := storage_backend.deny with input as {"resource": {"google_storage_bucket": {"state_bucket": [valid_state_bucket]}}}
	count(res) == 0
}

test_missing_uniform_access_rejected if {
	bad_b := object.union(valid_state_bucket, {"uniform_bucket_level_access": false})
	res := storage_backend.deny with input as {"resource": {"google_storage_bucket": {"state_bucket": [bad_b]}}}
	count(res) > 0
	some r in res
	contains(r, "must explicitly set uniform_bucket_level_access = true")
}

test_missing_public_access_prevention_rejected if {
	bad_b := object.union(valid_state_bucket, {"public_access_prevention": "inherited"})
	res := storage_backend.deny with input as {"resource": {"google_storage_bucket": {"state_bucket": [bad_b]}}}
	count(res) > 0
	some r in res
	contains(r, "public_access_prevention = 'enforced'")
}

test_missing_versioning_rejected if {
	bad_b := object.union(valid_state_bucket, {"versioning": []})
	res := storage_backend.deny with input as {"resource": {"google_storage_bucket": {"state_bucket": [bad_b]}}}
	count(res) > 0
	some r in res
	contains(r, "must enable object versioning")
}

test_versioning_disabled_rejected if {
	bad_b := object.union(valid_state_bucket, {"versioning": [{"enabled": false}]})
	res := storage_backend.deny with input as {"resource": {"google_storage_bucket": {"state_bucket": [bad_b]}}}
	count(res) > 0
	some r in res
	contains(r, "must enable object versioning")
}

test_force_destroy_true_rejected if {
	bad_b := object.union(valid_state_bucket, {"force_destroy": true})
	res := storage_backend.deny with input as {"resource": {"google_storage_bucket": {"state_bucket": [bad_b]}}}
	count(res) > 0
	some r in res
	contains(r, "must not set force_destroy = true")
}

test_invalid_cmek_format_rejected if {
	bad_b := object.union(valid_state_bucket, {
		"encryption": [{"default_kms_key_name": "arn:aws:kms:us-east-1:123456789012:key/abc"}],
	})
	res := storage_backend.deny with input as {"resource": {"google_storage_bucket": {"state_bucket": [bad_b]}}}
	count(res) > 0
	some r in res
	contains(r, "invalid KMS key format")
}

# ------------------------------------------------------------------------------
# Unit Tests: ACL & IAM Security
# ------------------------------------------------------------------------------
test_public_allusers_acl_rejected if {
	bad_acl := {"role_entity": ["READER:allUsers"]}
	res := storage_backend.deny with input as {"resource": {"google_storage_bucket_acl": {"public_acl": [bad_acl]}}}
	count(res) > 0
	some r in res
	contains(r, "grants public access to 'allUsers'")
}

test_public_predefined_acl_rejected if {
	bad_acl := {"predefined_acl": "publicRead"}
	res := storage_backend.deny with input as {"resource": {"google_storage_bucket_acl": {"public_acl": [bad_acl]}}}
	count(res) > 0
	some r in res
	contains(r, "disallowed public predefined_acl 'publicRead'")
}

test_public_iam_member_rejected if {
	bad_member := {"member": "allUsers", "role": "roles/storage.objectViewer"}
	res := storage_backend.deny with input as {"resource": {"google_storage_bucket_iam_member": {"public_mem": [bad_member]}}}
	count(res) > 0
	some r in res
	contains(r, "exposes bucket to public principal 'allUsers'")
}

test_public_iam_binding_rejected if {
	bad_binding := {"members": ["user:dev@example.com", "allAuthenticatedUsers"], "role": "roles/storage.objectAdmin"}
	res := storage_backend.deny with input as {"resource": {"google_storage_bucket_iam_binding": {"public_bind": [bad_binding]}}}
	count(res) > 0
	some r in res
	contains(r, "exposes bucket to public principal 'allAuthenticatedUsers'")
}

# ------------------------------------------------------------------------------
# Unit Tests: Backend 'gcs' Block Contract
# ------------------------------------------------------------------------------
test_valid_backend_block_accepted if {
	backend := {
		"bucket": "my-infraflow-tfstate",
		"prefix": "terraform/state/prod",
	}
	res := storage_backend.deny with input as {"backend": {"gcs": backend}}
	count(res) == 0
}

test_empty_backend_bucket_rejected if {
	backend := {
		"bucket": "",
		"prefix": "terraform/state/prod",
	}
	res := storage_backend.deny with input as {"backend": {"gcs": backend}}
	count(res) > 0
	some r in res
	contains(r, "must specify a non-empty 'bucket'")
}

test_reserved_goog_backend_bucket_rejected if {
	backend := {
		"bucket": "google-state-bucket",
		"prefix": "terraform/state/prod",
	}
	res := storage_backend.deny with input as {"backend": {"gcs": backend}}
	count(res) > 0
	some r in res
	contains(r, "must not start with reserved prefix 'google'")
}

test_leading_slash_backend_prefix_rejected if {
	backend := {
		"bucket": "valid-state-bucket",
		"prefix": "/terraform/state",
	}
	res := storage_backend.deny with input as {"backend": {"gcs": backend}}
	count(res) > 0
	some r in res
	contains(r, "must not start with a leading slash")
}

test_traversal_backend_prefix_rejected if {
	backend := {
		"bucket": "valid-state-bucket",
		"prefix": "terraform/../../etc",
	}
	res := storage_backend.deny with input as {"backend": {"gcs": backend}}
	count(res) > 0
	some r in res
	contains(r, "must not contain directory traversal '..'")
}
