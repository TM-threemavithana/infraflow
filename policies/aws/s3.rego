package aws.s3

import rego.v1

disallowed_acls := {"public-read", "public-read-write", "website"}

# Rule 1: Deny S3 bucket with public ACL
deny contains msg if {
	some name
	bucket := input.resource.aws_s3_bucket[name][_]
	disallowed_acls[bucket.acl]
	msg := sprintf("Resource 'aws_s3_bucket.%v' must not specify public ACL '%v'", [name, bucket.acl])
}

# Rule 2: Deny public access block unless all protections are explicitly true
deny contains msg if {
	some name
	pab := input.resource.aws_s3_bucket_public_access_block[name][_]
	object.get(pab, "block_public_acls", false) != true
	msg := sprintf("Resource 'aws_s3_bucket_public_access_block.%v' must explicitly set block_public_acls to true", [name])
}

deny contains msg if {
	some name
	pab := input.resource.aws_s3_bucket_public_access_block[name][_]
	object.get(pab, "block_public_policy", false) != true
	msg := sprintf("Resource 'aws_s3_bucket_public_access_block.%v' must explicitly set block_public_policy to true", [name])
}

deny contains msg if {
	some name
	pab := input.resource.aws_s3_bucket_public_access_block[name][_]
	object.get(pab, "ignore_public_acls", false) != true
	msg := sprintf("Resource 'aws_s3_bucket_public_access_block.%v' must explicitly set ignore_public_acls to true", [name])
}

deny contains msg if {
	some name
	pab := input.resource.aws_s3_bucket_public_access_block[name][_]
	object.get(pab, "restrict_public_buckets", false) != true
	msg := sprintf("Resource 'aws_s3_bucket_public_access_block.%v' must explicitly set restrict_public_buckets to true", [name])
}
