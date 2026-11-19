output "app_identifier" {
  description = "The canonical application identifier"
  value       = terraform_data.app_config.input.identifier
}

output "replica_count" {
  description = "Total number of simulated replicas provisioned"
  value       = length(terraform_data.replicas)
}

output "active_replicas" {
  description = "List of simulated replica node identifiers"
  value       = [for r in terraform_data.replicas : r.input.instance_id]
}

output "deployment_metadata" {
  description = "Deployment metadata map"
  value = {
    environment = var.environment
    app_name    = var.app_name
    tags        = terraform_data.app_config.input.tags
  }
}
