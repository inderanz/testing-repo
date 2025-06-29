# BAD SECURITY PRACTICES - This file contains intentional security vulnerabilities
# for testing the PR review agent

# 1. Hardcoded credentials - SECURITY ISSUE
variable "aws_access_key" {
  description = "AWS Access Key"
  default     = "AKIAIOSFODNN7EXAMPLE"  # Hardcoded access key
}

variable "aws_secret_key" {
  description = "AWS Secret Key"
  default     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Hardcoded secret key
}

# 2. Overly permissive security group - SECURITY ISSUE
resource "aws_security_group" "bad_security_group" {
  name        = "bad-security-group"
  description = "Security group with overly permissive rules"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Allows all traffic from anywhere
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Allows all outbound traffic
  }
}

# 3. Public S3 bucket with no encryption - SECURITY ISSUE
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket-12345"
}

resource "aws_s3_bucket_public_access_block" "public_bucket_access" {
  bucket = aws_s3_bucket.public_bucket.id

  block_public_acls       = false  # Allows public ACLs
  block_public_policy     = false  # Allows public policies
  ignore_public_acls      = false  # Doesn't ignore public ACLs
  restrict_public_buckets = false  # Doesn't restrict public buckets
}

resource "aws_s3_bucket_acl" "public_bucket_acl" {
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "public-read"  # Makes bucket publicly readable
}

# 4. EC2 instance with root user and no encryption - SECURITY ISSUE
resource "aws_instance" "bad_instance" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"

  root_block_device {
    volume_size = 20
    encrypted   = false  # No encryption on root volume
  }

  user_data = <<-EOF
              #!/bin/bash
              # Run as root user - SECURITY ISSUE
              sudo su -
              echo "root:password123" | chpasswd  # Hardcoded password
              EOF

  vpc_security_group_ids = [aws_security_group.bad_security_group.id]
}

# 5. IAM role with overly permissive policy - SECURITY ISSUE
resource "aws_iam_role" "bad_role" {
  name = "bad-iam-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "bad_policy" {
  name = "bad-policy"
  role = aws_iam_role.bad_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"  # Allows all actions - SECURITY ISSUE
        Resource = "*"  # Allows all resources - SECURITY ISSUE
      }
    ]
  })
}

# 6. RDS instance with no encryption and public access - SECURITY ISSUE
resource "aws_db_instance" "bad_database" {
  identifier = "bad-database"

  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_encrypted = false  # No encryption - SECURITY ISSUE

  db_name  = "mydb"
  username = "admin"
  password = "password123"  # Hardcoded password - SECURITY ISSUE

  publicly_accessible = true  # Publicly accessible - SECURITY ISSUE
  skip_final_snapshot = true  # No backup - SECURITY ISSUE
}

# 7. Lambda function with hardcoded secrets - SECURITY ISSUE
resource "aws_lambda_function" "bad_lambda" {
  filename         = "lambda_function.zip"
  function_name    = "bad-lambda"
  role            = aws_iam_role.bad_role.arn
  handler         = "index.handler"
  runtime         = "nodejs18.x"

  environment {
    variables = {
      DATABASE_URL = "mysql://admin:password123@bad-database.region.rds.amazonaws.com:3306/mydb"  # Hardcoded connection string
      API_KEY      = "sk-1234567890abcdef"  # Hardcoded API key
      SECRET_TOKEN = "super-secret-token-123"  # Hardcoded secret
    }
  }
}

# 8. CloudWatch log group with no retention - COMPLIANCE ISSUE
resource "aws_cloudwatch_log_group" "bad_log_group" {
  name = "/aws/lambda/bad-lambda"
  # No retention_in_days specified - logs will never expire
}

# 9. VPC with default settings - BEST PRACTICE ISSUE
resource "aws_vpc" "bad_vpc" {
  cidr_block = "10.0.0.0/16"
  # No tags specified - BEST PRACTICE ISSUE
  # No DNS settings specified
}

# 10. Auto Scaling Group with no health checks - BEST PRACTICE ISSUE
resource "aws_autoscaling_group" "bad_asg" {
  name                = "bad-asg"
  desired_capacity    = 2
  max_size           = 4
  min_size           = 1
  target_group_arns  = []
  vpc_zone_identifier = []

  launch_template {
    id      = "lt-12345678"
    version = "$Latest"
  }
  # No health check grace period specified
  # No health check type specified
} 