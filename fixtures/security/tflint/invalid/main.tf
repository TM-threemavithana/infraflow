terraform {
  required_version = ">= 1.6.0"
}

// Invalid legacy comment syntax should trigger terraform_comment_syntax
variable "BAD_CAMEL_CASE_UNTYPED" {
  default = "untyped_and_bad_naming"
}

variable "unused_variable" {
  type        = string
  description = "This variable is never referenced anywhere"
  default     = "orphaned"
}

resource "terraform_data" "bad_resource" {
  input = {
    test = "${var.BAD_CAMEL_CASE_UNTYPED}"
  }
}
