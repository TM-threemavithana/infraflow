terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Insecure Fixture: Public unencrypted S3 bucket
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "infraflow-insecure-public-bucket"
}

resource "aws_s3_bucket_public_access_block" "insecure_public_block" {
  bucket = aws_s3_bucket.insecure_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
