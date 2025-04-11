output "kali_instance_id" {
  description = "ID of the Kali Linux instance"
  value       = module.kali_instance.instance_id
}

output "kali_instance_private_ip" {
  description = "Private IP address of the Kali Linux instance"
  value       = module.kali_instance.instance_private_ip
}

output "kali_cloudwatch_log_group" {
  description = "Name of the CloudWatch Log Group for Kali instance logs"
  value       = aws_cloudwatch_log_group.kali_logs.name
}

output "kali_ssm_role_arn" {
  description = "ARN of the IAM role for SSM"
  value       = module.kali_instance.ssm_role_arn
}

output "kali_security_group_id" {
  description = "ID of the security group"
  value       = module.kali_instance.security_group_id
}