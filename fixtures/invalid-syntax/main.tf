# Deliberately invalid Terraform configuration for negative testing
resource "terraform_data" "broken" {
  malformed_attribute =
}
