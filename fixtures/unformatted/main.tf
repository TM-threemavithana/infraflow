# Deliberately unformatted configuration for negative testing
resource "terraform_data" "unformatted"{
input="misaligned"
    triggers_replace=[ 1,2,   3 ]
}
