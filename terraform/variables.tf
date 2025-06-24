# Variables for the Terraform configuration

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
  # Missing validation for allowed values
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
  # Missing validation for allowed instance types
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
  # Missing validation for CIDR format
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
  # Missing validation for allowed regions
}

variable "bucket_name" {
  description = "S3 bucket name"
  type        = string
  default     = "my-unique-data-bucket-12345"
  # Missing validation for bucket naming conventions
} 