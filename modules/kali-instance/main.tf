# Find the latest Kali Linux AMI in the AWS Marketplace
data "aws_ami" "kali_linux" {
  most_recent = true
  owners      = ["679593333241"] # Official Kali Linux AMI owner ID

  filter {
    name   = "name"
    values = ["kali-linux-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

# Create IAM role for SSM Fleet Manager
resource "aws_iam_role" "kali_ssm_role" {
  name = "${var.name_prefix}-ssm-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Effect = "Allow",
        Sid    = ""
      }
    ]
  })

  tags = {
    Name        = "${var.name_prefix}-ssm-role"
    Environment = var.environment
  }
}

# Attach AWS managed SSM policy for Fleet Manager and Inventory
resource "aws_iam_role_policy_attachment" "ssm_managed_instance_core" {
  role       = aws_iam_role.kali_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Create CloudWatch logs policy for sending logs
resource "aws_iam_policy" "cloudwatch_logs_policy" {
  name        = "${var.name_prefix}-cloudwatch-logs-policy"
  description = "Policy to allow sending logs to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ],
        Effect   = "Allow",
        Resource = "arn:aws:logs:*:*:log-group:/aws/ec2/${var.name_prefix}-kali-instance:*"
      }
    ]
  })
}

# Attach CloudWatch logs policy to the role
resource "aws_iam_role_policy_attachment" "cloudwatch_logs_policy_attachment" {
  role       = aws_iam_role.kali_ssm_role.name
  policy_arn = aws_iam_policy.cloudwatch_logs_policy.arn
}

# Create instance profile for the role
resource "aws_iam_instance_profile" "kali_instance_profile" {
  name = "${var.name_prefix}-instance-profile"
  role = aws_iam_role.kali_ssm_role.name
}

# Security Group for Kali Linux instance
resource "aws_security_group" "kali_sg" {
  name        = "${var.name_prefix}-security-group"
  description = "Security Group for Kali Linux instance"
  vpc_id      = var.vpc_id

  # Allow SSM connections
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS outbound for SSM"
  }

  tags = {
    Name        = "${var.name_prefix}-security-group"
    Environment = var.environment
  }
}

# Calculate the termination timestamp
locals {
  # Calculate termination time in UTC format
  termination_timestamp = timeadd(timestamp(), "${var.auto_termination_time}h")
}

# Create SQS queue for Lambda DLQ
resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "${var.name_prefix}-lambda-dlq"
  message_retention_seconds = 1209600  # 14 days
  
  # Enable server-side encryption
  sqs_managed_sse_enabled = true
  
  tags = merge(
    {
      Name        = "${var.name_prefix}-lambda-dlq"
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.additional_tags
  )
}

# Optional Lambda code signing configuration (disabled by default)
resource "aws_lambda_code_signing_config" "auto_terminate_signing_config" {
  description = "Code signing configuration for Kali auto-termination Lambda"
  
  allowed_publishers {
    signing_profile_version_arns = length(var.lambda_signing_profile_version_arns) > 0 ? var.lambda_signing_profile_version_arns : ["arn:aws:signer:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:signing-profile/DefaultLambdaSigningProfile"]
  }
  
  policies {
    untrusted_artifact_on_deployment = "Enforce"
  }
}

# Get current region
data "aws_region" "current" {}

# Auto-termination Lambda function
resource "aws_lambda_function" "auto_terminate" {
  function_name = "${var.name_prefix}-auto-terminate"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"  # Updated to a supported runtime
  timeout       = 30
  reserved_concurrent_executions = 1  # Limit concurrent executions

  # Place Lambda in VPC for better security
  vpc_config {
    subnet_ids         = [var.subnet_id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  # Enable X-Ray tracing
  tracing_config {
    mode = "Active"
  }

  # Configure DLQ
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  # Encrypt environment variables
  environment {
    variables = {
      INSTANCE_ID = aws_instance.kali_instance.id
    }
  }
  
  # Configure code signing by default
  code_signing_config_arn = aws_lambda_code_signing_config.auto_terminate_signing_config.arn
  
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  
  # Server-side encryption for environment variables
  kms_key_arn = aws_kms_key.lambda_key.arn
}

# Security group for Lambda function
resource "aws_security_group" "lambda_sg" {
  name        = "${var.name_prefix}-lambda-sg"
  description = "Security Group for Kali Linux auto-termination Lambda function"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS outbound for AWS API calls"
  }

  tags = merge(
    {
      Name        = "${var.name_prefix}-lambda-sg"
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.additional_tags
  )
}

# KMS key for Lambda environment variables
resource "aws_kms_key" "lambda_key" {
  description             = "KMS key for Lambda environment variable encryption"
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
        Sid    = "Allow Lambda to use the key",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      }
    ]
  })

  tags = merge(
    {
      Name        = "${var.name_prefix}-lambda-key"
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.additional_tags
  )
}

resource "aws_kms_alias" "lambda_key_alias" {
  name          = "alias/${var.name_prefix}-lambda-key"
  target_key_id = aws_kms_key.lambda_key.key_id
}

# Get current account ID
data "aws_caller_identity" "current" {}

# Create Lambda zip file
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_function.zip"
  
  source {
    content = <<EOF
const AWS = require('aws-sdk');
const ec2 = new AWS.EC2();

exports.handler = async (event) => {
    console.log('Auto-termination for Kali Linux instance triggered');
    
    const instanceId = process.env.INSTANCE_ID;
    
    if (!instanceId) {
        return {
            statusCode: 400,
            body: JSON.stringify('Instance ID not provided'),
        };
    }
    
    try {
        // First stop the instance
        console.log(`Stopping instance ${instanceId}`);
        await ec2.stopInstances({
            InstanceIds: [instanceId]
        }).promise();
        
        // Wait for the instance to stop
        console.log(`Waiting for instance ${instanceId} to stop`);
        await ec2.waitFor('instanceStopped', {
            InstanceIds: [instanceId]
        }).promise();
        
        // Then terminate it
        console.log(`Terminating instance ${instanceId}`);
        await ec2.terminateInstances({
            InstanceIds: [instanceId]
        }).promise();
        
        return {
            statusCode: 200,
            body: JSON.stringify(`Successfully initiated termination of instance ${instanceId}`),
        };
    } catch (error) {
        console.error('Error terminating instance:', error);
        return {
            statusCode: 500,
            body: JSON.stringify(`Error terminating instance: ${error.message}`),
        };
    }
};
EOF
    filename = "index.js"
  }
}

# Create IAM role for Lambda function
resource "aws_iam_role" "lambda_role" {
  name = "${var.name_prefix}-lambda-role"

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

  tags = merge(
    {
      Name        = "${var.name_prefix}-lambda-role"
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.additional_tags
  )
}

# Create IAM policy for Lambda to terminate EC2 instances
resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.name_prefix}-lambda-terminate-policy"
  description = "Policy to allow Lambda to terminate specific EC2 instance"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:DescribeInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances"
        ]
        Effect   = "Allow"
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Name" = "${var.name_prefix}-kali-instance"
          }
        }
      },
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Attach policy to Lambda role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# Create CloudWatch Event Rule for auto-termination
resource "aws_cloudwatch_event_rule" "auto_terminate" {
  name                = "${var.name_prefix}-auto-terminate"
  description         = "Trigger to automatically terminate the Kali Linux instance after the specified time"
  schedule_expression = "cron(${formatdate("m H d M ? Y", local.termination_timestamp)})" # Convert to cron format

  tags = merge(
    {
      Name        = "${var.name_prefix}-auto-terminate"
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.additional_tags
  )
}

# Set Lambda as target for CloudWatch Event
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.auto_terminate.name
  target_id = "auto-terminate-kali"
  arn       = aws_lambda_function.auto_terminate.arn
}

# Grant permission for CloudWatch Events to invoke Lambda function
resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auto_terminate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.auto_terminate.arn
}

# Launch EC2 instance with Kali Linux AMI
resource "aws_instance" "kali_instance" {
  ami                    = data.aws_ami.kali_linux.id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  private_ip             = var.private_ip  # Use the specified private IP if provided
  vpc_security_group_ids = [aws_security_group.kali_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.kali_instance_profile.name
  key_name               = var.key_name
  monitoring             = true  # Enable detailed monitoring for the instance
  ebs_optimized          = true  # Enable EBS optimization for better disk performance

  # Setup the instance to register with SSM and send logs to CloudWatch
  user_data = <<-EOF
    #!/bin/bash
    
    # Set up logging
    exec > >(tee /var/log/user-data.log|logger -t user-data) 2>&1
    echo "Starting user data script execution at $(date)"
    
    # Wait for cloud-init to complete
    echo "Waiting for cloud-init to complete..."
    cloud-init status --wait

    # Update package repositories
    echo "Updating package repositories..."
    apt-get update -y || { echo "Failed to update package repositories"; exit 1; }
    
    # Install essential dependencies
    echo "Installing essential dependencies..."
    apt-get install -y curl wget unzip jq python3-pip systemd || { echo "Failed to install essential dependencies"; exit 1; }

    # Install AWS CLI if not present
    if ! command -v aws &> /dev/null; then
        echo "Installing AWS CLI..."
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
        unzip awscliv2.zip
        ./aws/install
        rm -rf aws awscliv2.zip
    else
        echo "AWS CLI is already installed"
    fi

    # Configure AWS region
    export AWS_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
    echo "AWS Region: $AWS_REGION"

    # Install SSM agent
    echo "Installing SSM agent..."
    mkdir -p /tmp/ssm
    cd /tmp/ssm
    wget https://s3.$AWS_REGION.amazonaws.com/amazon-ssm-$AWS_REGION/latest/debian_amd64/amazon-ssm-agent.deb
    dpkg -i amazon-ssm-agent.deb || { echo "Failed to install SSM agent"; exit 1; }
    systemctl enable amazon-ssm-agent
    systemctl restart amazon-ssm-agent
    systemctl status amazon-ssm-agent
    cd -
    rm -rf /tmp/ssm

    # Install CloudWatch agent
    echo "Installing CloudWatch agent..."
    mkdir -p /tmp/cw-agent
    cd /tmp/cw-agent
    wget https://s3.$AWS_REGION.amazonaws.com/amazoncloudwatch-agent-$AWS_REGION/debian/amd64/latest/amazon-cloudwatch-agent.deb
    dpkg -i amazon-cloudwatch-agent.deb || { echo "Failed to install CloudWatch agent"; exit 1; }
    cd -
    rm -rf /tmp/cw-agent

    # Configure CloudWatch agent
    echo "Configuring CloudWatch agent..."
    mkdir -p /opt/aws/amazon-cloudwatch-agent/etc/
    cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'CONFIG'
    {
      "agent": {
        "metrics_collection_interval": 60,
        "run_as_user": "root"
      },
      "logs": {
        "logs_collected": {
          "files": {
            "collect_list": [
              {
                "file_path": "/var/log/auth.log",
                "log_group_name": "/aws/ec2/${var.name_prefix}-kali-instance",
                "log_stream_name": "{instance_id}/auth.log",
                "retention_in_days": 365
              },
              {
                "file_path": "/var/log/syslog",
                "log_group_name": "/aws/ec2/${var.name_prefix}-kali-instance",
                "log_stream_name": "{instance_id}/syslog",
                "retention_in_days": 365
              },
              {
                "file_path": "/var/log/user-data.log",
                "log_group_name": "/aws/ec2/${var.name_prefix}-kali-instance",
                "log_stream_name": "{instance_id}/user-data.log",
                "retention_in_days": 365
              },
              {
                "file_path": "/root/.bash_history",
                "log_group_name": "/aws/ec2/${var.name_prefix}-kali-instance",
                "log_stream_name": "{instance_id}/bash_history",
                "retention_in_days": 365
              },
              {
                "file_path": "/var/log/apt/history.log",
                "log_group_name": "/aws/ec2/${var.name_prefix}-kali-instance",
                "log_stream_name": "{instance_id}/apt_history.log",
                "retention_in_days": 365
              },
              {
                "file_path": "/var/log/aws/ssm/amazon-ssm-agent.log",
                "log_group_name": "/aws/ec2/${var.name_prefix}-kali-instance",
                "log_stream_name": "{instance_id}/ssm_agent.log",
                "retention_in_days": 365
              }
            ]
          }
        }
      }
    }
    CONFIG

    # Verify CloudWatch configuration
    echo "Verifying CloudWatch configuration..."
    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a verify -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json || { echo "Invalid CloudWatch agent configuration"; exit 1; }

    # Start the CloudWatch agent
    echo "Starting CloudWatch agent..."
    systemctl enable amazon-cloudwatch-agent
    systemctl restart amazon-cloudwatch-agent
    systemctl status amazon-cloudwatch-agent

    # Install additional Kali forensic tools for security operations
    echo "Installing additional forensic tools..."
    apt-get install -y forensics-all volatility autopsy sleuthkit || echo "Some forensic tools couldn't be installed - continuing"

    # Create a ready file to indicate successful setup
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Instance setup completed successfully" > /var/log/instance-setup-complete

    echo "User data script execution completed at $(date)"
  EOF

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = var.root_volume_type
    encrypted             = true
    delete_on_termination = true
  }

  # Tags with auto-termination information
  tags = merge(
    {
      Name                      = "${var.name_prefix}-kali-instance"
      Environment               = var.environment
      ManagedBy                 = "terraform"
      Purpose                   = "security-forensics"
      AutoTerminationScheduled  = "true"
      AutoTerminationTimestamp  = local.termination_timestamp
    },
    var.additional_tags
  )

  volume_tags = merge(
    {
      Name        = "${var.name_prefix}-kali-volume"
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.additional_tags
  )
  
  # Ensure instance has time to send final logs before termination
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"  # IMDSv2 requirement for security
  }
}