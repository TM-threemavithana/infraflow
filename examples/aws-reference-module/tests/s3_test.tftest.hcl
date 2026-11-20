mock_provider "aws" {}

variables {
  bucket_name = "infraflow-test-bucket"
  environment = "prod"
  aws_region  = "us-east-1"
}

run "verify_bucket_configuration" {
  command = plan

  assert {
    condition     = aws_s3_bucket.storage.bucket == "infraflow-test-bucket"
    error_message = "Bucket name must match the configured variable"
  }

  assert {
    condition     = aws_s3_bucket.storage.tags["Environment"] == "prod"
    error_message = "Environment tag must be prod"
  }

  assert {
    condition     = aws_s3_bucket.storage.tags["Project"] == "InfraFlow"
    error_message = "Project tag must be InfraFlow"
  }

  assert {
    condition     = aws_s3_bucket.storage.tags["ManagedBy"] == "InfraFlow"
    error_message = "ManagedBy tag must be InfraFlow"
  }

  assert {
    condition     = aws_kms_key.storage.enable_key_rotation == true
    error_message = "KMS key rotation must be enabled"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.storage.block_public_acls == true
    error_message = "Public ACLs must be blocked"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.storage.block_public_policy == true
    error_message = "Public policy must be blocked"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.storage.ignore_public_acls == true
    error_message = "Public ACLs must be ignored"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.storage.restrict_public_buckets == true
    error_message = "Public buckets must be restricted"
  }
}
