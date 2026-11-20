mock_provider "google" {}

variables {
  project_id  = "infraflow-mock-project"
  region      = "us-central1"
  bucket_name = "infraflow-test-bucket"
  environment = "prod"
}

run "verify_gcs_bucket_configuration" {
  command = plan

  assert {
    condition     = google_storage_bucket.storage.name == "infraflow-test-bucket"
    error_message = "Bucket name must match the configured variable"
  }

  assert {
    condition     = google_storage_bucket.storage.location == "us-central1"
    error_message = "Bucket location must match the configured region"
  }

  assert {
    condition     = google_storage_bucket.storage.uniform_bucket_level_access == true
    error_message = "Uniform bucket-level access must be enabled"
  }

  assert {
    condition     = google_storage_bucket.storage.public_access_prevention == "enforced"
    error_message = "Public access prevention must be enforced"
  }

  assert {
    condition     = google_storage_bucket.storage.force_destroy == false
    error_message = "force_destroy must be false to prevent accidental deletion"
  }

  assert {
    condition     = google_storage_bucket.storage.versioning[0].enabled == true
    error_message = "Bucket object versioning must be enabled"
  }

  assert {
    condition     = google_storage_bucket.storage.labels["environment"] == "prod"
    error_message = "environment label must be prod"
  }

  assert {
    condition     = google_storage_bucket.storage.labels["managed_by"] == "terraform"
    error_message = "managed_by label must be terraform"
  }

  assert {
    condition     = google_storage_bucket.storage.labels["project"] == "infraflow"
    error_message = "project label must be infraflow"
  }

  assert {
    condition     = google_kms_crypto_key.storage_key.rotation_period == "7776000s"
    error_message = "KMS crypto key rotation period must be 90 days"
  }
}
