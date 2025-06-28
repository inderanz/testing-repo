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

output "iam_policy_arn" {
  description = "ARN of the IAM policy"
  value       = aws_iam_policy.test_policy.arn
} 