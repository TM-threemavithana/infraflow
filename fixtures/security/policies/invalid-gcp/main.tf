terraform {
  required_version = ">= 1.6.0"
}

resource "google_storage_bucket" "insecure_gcs" {
  name                        = "infraflow-insecure-gcs-bucket"
  location                    = "US"
  uniform_bucket_level_access = false
}
