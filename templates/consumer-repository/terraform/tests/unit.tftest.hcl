# InfraFlow Native Unit Test Suite
# Validates module inputs and outputs offline without cloud credentials.

run "verify_workload_defaults" {
  command = plan

  assert {
    condition     = var.environment == "dev"
    error_message = "Default environment must be 'dev'."
  }

  assert {
    condition     = var.workload_name == "sample-service"
    error_message = "Default workload_name must be 'sample-service'."
  }

  assert {
    condition     = var.tags["ManagedBy"] == "infraflow"
    error_message = "Mandatory tag 'ManagedBy' must be set to 'infraflow'."
  }
}

run "verify_staging_configuration" {
  command = plan

  variables {
    workload_name = "staging-service"
    environment   = "staging"
    tags = {
      Environment = "staging"
      ManagedBy   = "infraflow"
      Service     = "staging-service"
    }
  }

  assert {
    condition     = var.environment == "staging"
    error_message = "Staging environment variable mismatch."
  }

  assert {
    condition     = var.workload_name == "staging-service"
    error_message = "Staging workload_name variable mismatch."
  }
}
