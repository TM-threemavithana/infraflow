# Unit test suite for InfraFlow cloud-free module using native Terraform 1.6+ testing

variables {
  app_name    = "infraflow-demo"
  environment = "dev"
  replicas    = 2
}

run "unit_default_configuration" {
  command = plan

  assert {
    condition     = output.app_identifier == "dev-infraflow-demo"
    error_message = "Computed app_identifier did not match expected value"
  }

  assert {
    condition     = output.replica_count == 2
    error_message = "Default replica count should be 2"
  }

  assert {
    condition     = length(output.active_replicas) == 2
    error_message = "Active replicas list length should be 2"
  }

  assert {
    condition     = output.deployment_metadata.environment == "dev"
    error_message = "Metadata environment does not match input"
  }
}

run "unit_custom_replica_count_and_tags" {
  command = plan

  variables {
    replicas    = 5
    environment = "prod"
    app_name    = "payment-svc"
    tags = {
      CostCenter = "finance-101"
      Tier       = "mission-critical"
    }
  }

  assert {
    condition     = output.app_identifier == "prod-payment-svc"
    error_message = "Custom app_identifier mismatch"
  }

  assert {
    condition     = output.replica_count == 5
    error_message = "Custom replica count should be 5"
  }

  assert {
    condition     = output.active_replicas[0] == "prod-payment-svc-node-1"
    error_message = "First replica identifier mismatch"
  }

  assert {
    condition     = output.active_replicas[4] == "prod-payment-svc-node-5"
    error_message = "Fifth replica identifier mismatch"
  }

  assert {
    condition     = output.deployment_metadata.tags.CostCenter == "finance-101"
    error_message = "Custom tag CostCenter was not preserved"
  }

  assert {
    condition     = output.deployment_metadata.tags.Environment == "prod"
    error_message = "Merged environment tag was not present"
  }

  assert {
    condition     = output.deployment_metadata.tags.Application == "payment-svc"
    error_message = "Merged application tag was not present"
  }
}

run "validation_invalid_environment" {
  command = plan

  variables {
    environment = "invalid-env"
  }

  expect_failures = [
    var.environment
  ]
}

run "validation_invalid_replica_count_low" {
  command = plan

  variables {
    replicas = 0
  }

  expect_failures = [
    var.replicas
  ]
}

run "validation_invalid_replica_count_high" {
  command = plan

  variables {
    replicas = 11
  }

  expect_failures = [
    var.replicas
  ]
}

run "validation_invalid_app_name_pattern" {
  command = plan

  variables {
    app_name = "INVALID_NAME!"
  }

  expect_failures = [
    var.app_name
  ]
}
