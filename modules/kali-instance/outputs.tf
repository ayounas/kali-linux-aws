output "instance_id" {
  description = "ID of the Kali Linux instance"
  value       = aws_instance.kali_instance.id
}

output "instance_private_ip" {
  description = "Private IP address of the Kali Linux instance"
  value       = aws_instance.kali_instance.private_ip
}

output "instance_arn" {
  description = "ARN of the Kali Linux instance"
  value       = aws_instance.kali_instance.arn
}

output "ssm_role_arn" {
  description = "ARN of the IAM role for SSM"
  value       = aws_iam_role.kali_ssm_role.arn
}

output "security_group_id" {
  description = "ID of the security group"
  value       = aws_security_group.kali_sg.id
}