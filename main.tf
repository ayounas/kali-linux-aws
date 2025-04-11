provider "aws" {
  region = var.aws_region
}

module "kali_instance" {
  source = "./modules/kali-instance"
  
  vpc_id              = var.vpc_id
  subnet_id           = var.subnet_id
  private_ip          = var.private_ip
  instance_type       = var.instance_type
  key_name            = var.key_name
  environment         = var.environment
  name_prefix         = var.name_prefix
  root_volume_size    = var.root_volume_size
  root_volume_type    = var.root_volume_type
  auto_termination_time = var.auto_termination_time
  additional_tags     = var.additional_tags
  
  # Lambda code signing parameters
  enable_lambda_code_signing = var.enable_lambda_code_signing
  lambda_signing_profile_version_arns = var.lambda_signing_profile_version_arns
}

# Create a CloudWatch Log Group that will persist even when instances are destroyed
resource "aws_cloudwatch_log_group" "kali_logs" {
  name              = "/aws/ec2/${var.name_prefix}-kali-instance"
  retention_in_days = 365  # 1 year retention as per security best practices
  kms_key_id        = aws_kms_key.logs_key.arn
  
  # Prevent destruction of the log group when terraform destroy is run
  lifecycle {
    prevent_destroy = true
  }

  tags = {
    Name        = "${var.name_prefix}-kali-log-group"
    Environment = var.environment
  }
}

# KMS key for encrypting CloudWatch logs
resource "aws_kms_key" "logs_key" {
  description             = "KMS key for CloudWatch logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "Enable IAM User Permissions",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch to encrypt logs",
        Effect = "Allow",
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        },
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ],
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.name_prefix}-logs-kms-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "logs_key_alias" {
  name          = "alias/${var.name_prefix}-logs-key"
  target_key_id = aws_kms_key.logs_key.key_id
}

# Get current account ID
data "aws_caller_identity" "current" {}