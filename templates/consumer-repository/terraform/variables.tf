variable "workload_name" {
  type        = string
  description = "Name of the workload or service"
  default     = "sample-service"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$", var.workload_name))
    error_message = "workload_name must be a valid lowercase alphanumeric identifier."
  }
}

variable "environment" {
  type        = string
  description = "Target deployment environment"
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "tags" {
  type        = map(string)
  description = "Mandatory resource tags for governance compliance"
  default = {
    Environment = "dev"
    ManagedBy   = "infraflow"
    Service     = "sample-service"
  }

  validation {
    condition     = contains(keys(var.tags), "Environment") && contains(keys(var.tags), "ManagedBy")
    error_message = "tags must include both 'Environment' and 'ManagedBy' keys."
  }
}
