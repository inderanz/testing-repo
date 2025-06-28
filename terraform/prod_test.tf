# Production-grade Terraform test file for LLM review

# SECURITY ISSUE: Hardcoded AWS credentials
provider "aws" {
  access_key = "AKIAEXAMPLE"
  secret_key = "SECRETKEYEXAMPLE"
  region     = "us-west-2"
}

# SECURITY ISSUE: Overly permissive security group
resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Open to the world"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SECURITY ISSUE: Unencrypted S3 bucket
resource "aws_s3_bucket" "unencrypted" {
  bucket = "prod-test-unencrypted-bucket"
  acl    = "public-read"
} 