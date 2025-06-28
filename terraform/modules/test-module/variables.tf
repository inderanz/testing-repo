variable "environment" {
  description = "Environment name"
  type        = string
  default     = "test"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "test-project"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
} 