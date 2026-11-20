package aws.s3_test

import rego.v1
import data.aws.s3

test_s3_public_acl_denied if {
	mock_input := {"resource": {"aws_s3_bucket": {"bad": [{"bucket": "public-bkt", "acl": "public-read"}]}}}
	res := s3.deny with input as mock_input
	count(res) == 1
	contains(res[_], "must not specify public ACL")
}

test_s3_private_acl_allowed if {
	mock_input := {"resource": {"aws_s3_bucket": {"good": [{"bucket": "private-bkt", "acl": "private"}]}}}
	res := s3.deny with input as mock_input
	count(res) == 0
}

test_s3_public_access_block_denied_when_false if {
	mock_input := {"resource": {"aws_s3_bucket_public_access_block": {"bad_block": [{
		"block_public_acls": false,
		"block_public_policy": true,
		"ignore_public_acls": true,
		"restrict_public_buckets": true,
	}]}}}
	res := s3.deny with input as mock_input
	count(res) == 1
	contains(res[_], "must explicitly set block_public_acls to true")
}

test_s3_public_access_block_denied_when_omitted if {
	# Omitted attributes must not bypass policy
	mock_input := {"resource": {"aws_s3_bucket_public_access_block": {"omitted_block": [{
		"bucket": "test-id",
	}]}}}
	res := s3.deny with input as mock_input
	count(res) == 4 # All 4 required booleans are missing
}

test_s3_public_access_block_allowed_when_all_true if {
	mock_input := {"resource": {"aws_s3_bucket_public_access_block": {"good_block": [{
		"block_public_acls": true,
		"block_public_policy": true,
		"ignore_public_acls": true,
		"restrict_public_buckets": true,
	}]}}}
	res := s3.deny with input as mock_input
	count(res) == 0
}
