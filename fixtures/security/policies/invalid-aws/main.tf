terraform {
  required_version = ">= 1.6.0"
}

resource "aws_s3_bucket" "bad_acl_bucket" {
  bucket = "infraflow-public-read-bucket"
  acl    = "public-read"
}
