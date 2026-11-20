variable "bucket_name" {
  description = "Name of the S3 bucket to create"
  type        = string
  default     = "infraflow-ref-module-storage"
}

variable "environment" {
  description = "Deployment environment name (dev, staging, prod, test)"
  type        = string
  default     = "prod"
}

variable "aws_region" {
  description = "Target AWS region"
  type        = string
  default     = "us-east-1"
}
