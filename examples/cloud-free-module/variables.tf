variable "app_name" {
  type        = string
  description = "Unique application name (3-20 lowercase alphanumeric characters and hyphens)"
  default     = "infraflow-demo"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,20}$", var.app_name))
    error_message = "The app_name variable must be 3-20 lowercase alphanumeric characters or hyphens."
  }
}

variable "environment" {
  type        = string
  description = "Target deployment environment (dev, staging, or prod)"
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "The environment variable must be one of: dev, staging, prod."
  }
}

variable "replicas" {
  type        = number
  description = "Number of simulated compute instances to provision (1-10)"
  default     = 2

  validation {
    condition     = var.replicas >= 1 && var.replicas <= 10
    error_message = "The replicas variable must be between 1 and 10 inclusive."
  }
}

variable "tags" {
  type        = map(string)
  description = "Resource tags to attach to the infrastructure deployment"
  default = {
    ManagedBy = "InfraFlow"
    Platform  = "TerraformCore"
  }
}
