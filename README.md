# Kali Linux AWS Deployment

This project provides a secure, automated way to deploy Kali Linux instances in AWS with built-in security controls, logging, and auto-termination capabilities. The solution uses Terraform to deploy a Kali Linux instance that can be managed via AWS Systems Manager.

## Features

- **Latest Kali Linux AMI**: Automatically fetches the latest official Kali Linux AMI
- **SSM Fleet Manager Integration**: Access instances securely without SSH keys
- **CloudWatch Logging**: Persistent forensic-ready logs that survive instance termination
- **Auto-Termination**: Mandatory termination time to ensure instances aren't left running
- **Configurable Settings**: Customize instance type, volume size, and more
- **Security Best Practices**: Follows AWS security best practices

## Setup Instructions

### Prerequisites

- AWS CLI installed and configured
- Appropriate AWS permissions to create EC2 instances, IAM roles, and related resources
- Terraform (version 1.0+) installed

### Terraform Deployment

1. Create a `terraform.tfvars` file with required variables:
   ```
   aws_region = "eu-west-2"
   vpc_id = "vpc-xxxxxxxx"
   subnet_id = "subnet-xxxxxxxx"
   auto_termination_time = 24  # Hours
   ```

2. Initialize and apply:
   ```
   terraform init
   terraform apply
   ```

### CI/CD Pipeline Deployment

For automated deployments using a pipeline:

1. Ensure your pipeline environment has AWS credentials with appropriate permissions
2. Set the required Terraform variables as pipeline variables/parameters
3. Run the following commands in your pipeline:
   ```
   terraform init
   terraform validate
   terraform plan -out=tfplan
   terraform apply tfplan
   ```

## User Guide

### Accessing the Instance

The Kali Linux instance is configured for access through AWS Systems Manager:

1. In the AWS Console, go to AWS Systems Manager → Fleet Manager
2. Find your Kali instance in the list
3. Select it and click "Node actions → Connect"
4. Choose "Session Manager" to open a terminal session

### Auto-Termination

All Kali Linux instances will automatically terminate after the specified time period. This is a mandatory security control to ensure instances are not left running unnecessarily. The CloudWatch logs will remain available after instance termination for forensic purposes.

## Security Controls

- **IMDSv2 Requirement**: Prevents SSRF vulnerabilities
- **KMS-Encrypted Logs**: All CloudWatch logs are encrypted with KMS
- **Private Networking**: No public IP addresses assigned by default
- **Minimal IAM Permissions**: Follows least privilege principle
- **SSM Access**: No SSH keys required for access

## Troubleshooting

If you encounter issues:

1. **SSM Connection Failures**: Verify that the instance is running and has a "Connected" status in Systems Manager. Check that outbound HTTPS (443) traffic is allowed.

2. **CloudWatch Log Issues**: Check IAM permissions and ensure the CloudWatch agent is running on the instance.

3. **Terraform Apply Errors**: Make sure all required variables are set and that your AWS credentials have sufficient permissions.

For additional help, please contact the security team.