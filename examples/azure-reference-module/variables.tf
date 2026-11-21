variable "subscription_id" {
  description = "Target Azure Subscription ID (UUIDv4)"
  type        = string
  default     = "00000000-0000-0000-0000-000000000000"
}

variable "tenant_id" {
  description = "Microsoft Entra ID Tenant ID (UUIDv4)"
  type        = string
  default     = "00000000-0000-0000-0000-000000000000"
}

variable "client_id" {
  description = "Microsoft Entra ID Client ID (UUIDv4)"
  type        = string
  default     = "00000000-0000-0000-0000-000000000000"
}

variable "resource_group_name" {
  description = "Name of the Azure Resource Group"
  type        = string
  default     = "rg-infraflow-prod"
}

variable "location" {
  description = "Azure region for resource deployment"
  type        = string
  default     = "eastus"
}

variable "storage_account_name" {
  description = "Name of the Azure Storage Account (3-24 lowercase alphanumeric)"
  type        = string
  default     = "stinfraflowprod01"
}

variable "container_name" {
  description = "Name of the Azure Blob Storage Container"
  type        = string
  default     = "tfstate"
}

variable "environment" {
  description = "Deployment environment namespace"
  type        = string
  default     = "prod"
}

variable "tags" {
  description = "Resource tags for governance and compliance"
  type        = map(string)
  default = {
    environment = "prod"
    managed_by  = "terraform"
    project     = "infraflow"
  }
}
