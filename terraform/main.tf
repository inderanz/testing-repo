# Terraform configuration for a simple web application infrastructure
# This file contains various resources with some intentional issues for testing

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# VPC Configuration
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "main-vpc"
    Environment = "production"
  }
}

# Security Group with overly permissive rules (security issue)
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.main.id

  # Overly permissive ingress rule (security issue)
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all traffic"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "web-security-group"
  }
}

# EC2 Instance
resource "aws_instance" "web" {
  ami           = "ami-12345678"  # Hardcoded AMI (compliance issue)
  instance_type = "t3.micro"
  
  vpc_security_group_ids = [aws_security_group.web.id]
  
  # Missing user_data for proper configuration
  
  tags = {
    Name = "web-server"
    Environment = "production"
  }
}

# S3 Bucket without encryption (security issue)
resource "aws_s3_bucket" "data" {
  bucket = "my-unique-data-bucket-12345"
  
  # Missing encryption configuration
  # Missing versioning
  # Missing lifecycle policies
}

# IAM Role with overly permissive policy (security issue)
resource "aws_iam_role" "lambda_role" {
  name = "lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"  # Overly permissive (security issue)
        Resource = "*"
      }
    ]
  })
}

# Output values
output "vpc_id" {
  value = aws_vpc.main.id
}

output "instance_id" {
  value = aws_instance.web.id
} 