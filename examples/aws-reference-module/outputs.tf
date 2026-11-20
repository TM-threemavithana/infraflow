output "bucket_id" {
  description = "The ID of the created S3 bucket"
  value       = aws_s3_bucket.storage.id
}

output "bucket_arn" {
  description = "The ARN of the created S3 bucket"
  value       = aws_s3_bucket.storage.arn
}

output "kms_key_arn" {
  description = "The ARN of the KMS key used for S3 encryption"
  value       = aws_kms_key.storage.arn
}
