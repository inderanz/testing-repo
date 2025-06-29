# Intentionally bad Terraform for PR review agent test
resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-insecure-bucket"
  acl    = "public-read" # Insecure ACL
  versioning {
    enabled = "yes" # Wrong type, should be bool
  }
  logging {
    target_bucket = "" # Missing required value
  }
  # Deprecated argument
  force_destroy = 1 # Should be bool
  # Unsupported argument
  not_a_param = "oops"
}

resource "aws_security_group" "bad_sg" {
  name        = "bad-sg"
  description = "Allow all inbound traffic"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # Open to the world
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # Missing required tags
}

# Resource with missing required argument
resource "aws_instance" "bad_instance" {
  ami           = "ami-123456"
  # instance_type is missing
}
