locals {
  identifier = "${var.environment}-${var.app_name}"
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      Application = var.app_name
    }
  )
}

# Simulated application configuration state using built-in terraform_data
resource "terraform_data" "app_config" {
  input = {
    app_name    = var.app_name
    environment = var.environment
    identifier  = local.identifier
    tags        = local.common_tags
  }

  lifecycle {
    postcondition {
      condition     = length(self.output.identifier) > 0
      error_message = "Computed application identifier must not be empty."
    }
  }
}

# Simulated replica instances using built-in terraform_data
resource "terraform_data" "replicas" {
  count = var.replicas

  input = {
    instance_id = "${local.identifier}-node-${count.index + 1}"
    index       = count.index
    status      = "running"
  }

  triggers_replace = [
    terraform_data.app_config.output.identifier,
    count.index
  ]
}
