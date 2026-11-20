terraform {
  required_version = ">= 1.5.0"
}

variable "app_name" {
  type        = string
  description = "Application name for external consumer workload"
  default     = "consumer-service"

  validation {
    condition     = length(var.app_name) > 0
    error_message = "Application name must not be empty."
  }
}

variable "environment" {
  type        = string
  description = "Target deployment environment"
  default     = "production"

  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

resource "terraform_data" "consumer_resource" {
  input = {
    app_name    = var.app_name
    environment = var.environment
    managed_by  = "infraflow-platform"
  }
}

output "consumer_id" {
  description = "Generated ID of consumer resource"
  value       = terraform_data.consumer_resource.id
}
