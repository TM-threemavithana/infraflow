output "workload_id" {
  description = "Unique identifier of the deployed workload"
  value       = terraform_data.workload.id
}

output "workload_name" {
  description = "Configured name of the workload"
  value       = var.workload_name
}

output "environment" {
  description = "Deployment target environment"
  value       = var.environment
}
