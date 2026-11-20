variable "project_id" {
  description = "Google Cloud project ID (6 to 30 lowercase alphanumeric characters and hyphens)"
  type        = string
  default     = "infraflow-ref-project"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "The project_id must be 6 to 30 characters, starting with a letter, ending with an alphanumeric character, using only lowercase letters, digits, and hyphens."
  }
}

variable "region" {
  description = "Target Google Cloud region for infrastructure deployment"
  type        = string
  default     = "us-central1"

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]$", var.region))
    error_message = "The region must be a valid GCP region string format (e.g., us-central1, europe-west1)."
  }
}

variable "bucket_name" {
  description = "Globally unique name for the Google Cloud Storage bucket"
  type        = string
  default     = "infraflow-gcp-ref-storage"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9_.-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "The bucket_name must follow GCP bucket naming conventions (3-63 characters, lowercase letters, numbers, dashes, underscores, dots)."
  }
}

variable "environment" {
  description = "Deployment environment identifier (dev, staging, prod, test)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod", "test"], var.environment)
    error_message = "The environment must be one of: dev, staging, prod, test."
  }
}
