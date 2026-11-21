# InfraFlow Consumer Reference Module — 100% Cloud-Free
# Uses terraform_data to eliminate live cloud provider and credential dependencies.

terraform {
  required_version = ">= 1.6.0"
}

resource "terraform_data" "workload" {
  input = {
    workload_name = var.workload_name
    environment   = var.environment
    managed_by    = "infraflow"
    deployed_at   = timestamp()
  }

  lifecycle {
    create_before_destroy = true
  }
}
