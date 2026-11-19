# Valid Terraform configuration paired with an intentionally failing test
resource "terraform_data" "status" {
  input = "active"
}
