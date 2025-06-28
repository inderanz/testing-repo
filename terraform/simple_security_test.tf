# Simple Terraform file with obvious security issues for testing

# SECURITY ISSUE 1: Hardcoded credentials
variable "aws_access_key" {
  description = "AWS Access Key"
  type        = string
  default     = "AKIAIOSFODNN7EXAMPLE"  # SECURITY ISSUE: Hardcoded credentials
}

variable "aws_secret_key" {
  description = "AWS Secret Key"
  type        = string
  default     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # SECURITY ISSUE: Hardcoded credentials
}

# SECURITY ISSUE 2: Overly permissive security group
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
}

# SECURITY ISSUE 3: Instance without encryption
resource "aws_instance" "test_instance" {
  ami           = "ami-12345678"  # SECURITY ISSUE: Hardcoded AMI
  instance_type = "t2.micro"

  # SECURITY ISSUE: No encryption at rest
  root_block_device {
    volume_size = 20
    # Missing encryption = true
  }

  # SECURITY ISSUE: Hardcoded password in user data
  user_data = base64encode(<<-EOF
              #!/bin/bash
              echo "root:password123" | chpasswd  # SECURITY ISSUE: Hardcoded password
              EOF
  )
} 