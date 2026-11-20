output "bucket_name" {
  description = "Name of the provisioned Google Cloud Storage bucket"
  value       = google_storage_bucket.storage.name
}

output "bucket_url" {
  description = "Self-link / URL of the provisioned Google Cloud Storage bucket"
  value       = google_storage_bucket.storage.url
}

output "kms_key_id" {
  description = "Resource ID of the Cloud KMS cryptographic key securing state storage"
  value       = google_kms_crypto_key.storage_key.id
}
