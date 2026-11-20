terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Insecure Fixture: Security group with unrestricted 0.0.0.0/0 ingress on SSH (port 22)
resource "aws_security_group" "insecure_ssh" {
  name        = "insecure-ssh-sg"
  description = "Intentionally insecure security group exposing SSH to internet"

  ingress {
    description = "Unrestricted SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
