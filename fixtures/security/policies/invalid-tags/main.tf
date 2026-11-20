terraform {
  required_version = ">= 1.6.0"
}

resource "aws_s3_bucket" "missing_env_tag" {
  bucket = "infraflow-tagged-bucket"

  tags = {
    Project   = "infraflow"
    ManagedBy = "terraform"
    # Missing Environment tag
  }
}
