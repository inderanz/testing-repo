# Test Terraform Module with Security Issues
# This module is intentionally written with security vulnerabilities for testing

# Security Issue 1: Hardcoded credentials
variable "aws_access_key" {
  description = "AWS Access Key"
  type        = string
  default     = "AKIAIOSFODNN7EXAMPLE"  # Hardcoded credentials - SECURITY ISSUE
}

variable "aws_secret_key" {
  description = "AWS Secret Key"
  type        = string
  default     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Hardcoded credentials - SECURITY ISSUE
}

# Security Issue 2: Overly permissive security group
resource "aws_security_group" "test_sg" {
  name        = "test-security-group"
  description = "Test security group with overly permissive rules"

  # SECURITY ISSUE: Allowing all traffic from anywhere
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # SECURITY ISSUE: Too permissive
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # SECURITY ISSUE: Too permissive
  }

  tags = {
    Name = "test-security-group"
  }
}

# Security Issue 3: Instance without encryption
resource "aws_instance" "test_instance" {
  ami           = "ami-12345678"  # SECURITY ISSUE: Hardcoded AMI
  instance_type = "t2.micro"

  # SECURITY ISSUE: No encryption at rest
  root_block_device {
    volume_size = 20
    # Missing encryption = true
  }

  # SECURITY ISSUE: Using default security group
  vpc_security_group_ids = [aws_security_group.test_sg.id]

  # SECURITY ISSUE: No user data encryption
  user_data = base64encode(<<-EOF
              #!/bin/bash
              echo "root:password123" | chpasswd  # SECURITY ISSUE: Hardcoded password
              EOF
  )

  tags = {
    Name = "test-instance"
  }
}

# Security Issue 4: S3 bucket without encryption
resource "aws_s3_bucket" "test_bucket" {
  bucket = "my-test-bucket-${random_string.bucket_suffix.result}"

  # SECURITY ISSUE: No encryption configuration
  # SECURITY ISSUE: No versioning
  # SECURITY ISSUE: No access logging
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# Security Issue 5: IAM policy that's too permissive
resource "aws_iam_policy" "test_policy" {
  name        = "test-policy"
  description = "Test IAM policy with overly permissive permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"  # SECURITY ISSUE: Wildcard permissions
        Resource = "*"  # SECURITY ISSUE: Wildcard resources
      }
    ]
  })
}

# Outputs
output "instance_id" {
  description = "ID of the created instance"
  value       = aws_instance.test_instance.id
}

output "security_group_id" {
  description = "ID of the security group"
  value       = aws_security_group.test_sg.id
}

output "bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.test_bucket.bucket
} 