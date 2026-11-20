terraform {
  required_version = ">= 1.6.0"
}

variable "valid_identifier" {
  type        = string
  description = "A properly typed and named variable"
  default     = "infraflow-valid"
}

resource "terraform_data" "valid_node" {
  input = {
    id   = var.valid_identifier
    mode = "strict"
  }
}

output "node_id" {
  description = "Exported node identifier"
  value       = terraform_data.valid_node.input.id
}
