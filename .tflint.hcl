config {
  call_module_type = "local"
  force            = false
}

# Enforce explicit variable types
rule "terraform_typed_variables" {
  enabled = true
}

# Flag deprecated interpolation syntax (${var.foo}) where unneeded
rule "terraform_deprecated_interpolation" {
  enabled = true
}

# Flag deprecated index syntax
rule "terraform_deprecated_index" {
  enabled = true
}

# Flag unused variables or local declarations
rule "terraform_unused_declarations" {
  enabled = true
}

# Disallow legacy // comments in favor of #
rule "terraform_comment_syntax" {
  enabled = true
}

# Enforce explicit module version pinning
rule "terraform_module_version" {
  enabled = true
}

# Enforce terraform version constraint specification
rule "terraform_required_version" {
  enabled = true
}

# Enforce documented variables
rule "terraform_documented_variables" {
  enabled = true
}

# --- Cloud Ruleset Extensibility (Activated when plugins installed) ---
# plugin "aws" {
#   enabled = true
#   version = "0.38.0"
#   source  = "github.com/terraform-linters/tflint-ruleset-aws"
# }
