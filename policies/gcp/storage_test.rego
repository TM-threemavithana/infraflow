package gcp.storage_test

import rego.v1
import data.gcp.storage

test_gcs_uniform_access_denied_when_false if {
	mock_input := {"resource": {"google_storage_bucket": {"bad_bucket": [{"uniform_bucket_level_access": false}]}}}
	res := storage.deny with input as mock_input
	count(res) >= 1
	contains(res[_], "must explicitly set uniform_bucket_level_access to true")
}

test_gcs_uniform_access_denied_when_omitted if {
	mock_input := {"resource": {"google_storage_bucket": {"bad_bucket": [{"name": "no-uniform"}]}}}
	res := storage.deny with input as mock_input
	count(res) >= 1
}

test_gcs_uniform_access_allowed_when_true if {
	mock_input := {"resource": {"google_storage_bucket": {"good_bucket": [{"uniform_bucket_level_access": true}]}}}
	res := storage.deny with input as mock_input
	count(res) == 0
}
