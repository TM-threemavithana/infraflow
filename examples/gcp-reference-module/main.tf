provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_kms_key_ring" "keyring" {
  name     = "${var.bucket_name}-keyring"
  location = var.region
}

resource "google_kms_crypto_key" "storage_key" {
  name            = "${var.bucket_name}-key"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "7776000s" # 90 days

  labels = {
    environment = "prod"
    managed_by  = "terraform"
    project     = "infraflow"
  }
}

resource "google_storage_bucket" "storage" {
  name                        = var.bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.storage_key.id
  }

  labels = {
    environment = "prod"
    managed_by  = "terraform"
    project     = "infraflow"
  }
}
