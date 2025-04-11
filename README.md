# Kali Linux AWS Service Catalog

This project provides a secure, automated way to deploy Kali Linux instances in AWS with built-in security controls, logging, and auto-termination capabilities. The solution is packaged as an AWS Service Catalog item that allows users to self-service deploy Kali Linux instances while maintaining organizational security requirements.

## Features

- **Latest Kali Linux AMI**: Automatically fetches the latest official Kali Linux AMI
- **SSM Fleet Manager Integration**: Access instances securely without SSH keys
- **CloudWatch Logging**: Persistent forensic-ready logs that survive instance termination
- **Auto-Termination**: Mandatory termination time to ensure instances aren't left running
- **Configurable Settings**: Customize instance type, volume size, and more
- **Security Best Practices**: Follows AWS security best practices (verified with Checkov)

## Setup Instructions

### Prerequisites

- AWS CLI installed and configured
- Appropriate AWS permissions to create Service Catalog products, portfolios, and IAM roles
- Terraform (version 1.0+) installed (for local development only)

### Option 1: Deploy as Service Catalog Item (Recommended)

The easiest way to use this solution is to publish it to AWS Service Catalog:

1. Navigate to the project directory:
   ```
   cd /path/to/kali-linux-aws
   ```

2. Run the setup script:
   ```
   ./scripts/setup-catalog.sh
   ```

3. The script will:
   - Package Terraform code into an S3 bucket
   - Create a Service Catalog portfolio if it doesn't exist
   - Create a Service Catalog product for the Kali Linux deployment
   - Set up appropriate IAM roles and constraints
   - Grant access to your current IAM user

4. Once complete, users can deploy Kali Linux instances through the AWS Service Catalog console.

### Option 2: Direct Terraform Deployment

For development or testing purposes, you can deploy directly with Terraform:

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

## User Guide

### Deploying a Kali Linux Instance

1. Log into the AWS Management Console
2. Navigate to Service Catalog → Products
3. Find "Kali Linux Security Instance" and click "Launch Product"
4. Fill in the required parameters:
   - VPC ID and Subnet ID
   - Instance Type (default: t3.medium)
   - Root Volume Size (default: 30 GB)
   - Auto-Termination Time (required, in hours)

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

## Maintenance and Updates

To update the Kali Linux AWS Service Catalog product:

1. Make changes to the Terraform code
2. Update the version in the setup script (`PRODUCT_VERSION`)
3. Run the setup script again to publish a new version

## Troubleshooting

If you encounter issues:

1. **SSM Connection Failures**: Verify that the instance is running and has a "Connected" status in Systems Manager. Check that outbound HTTPS (443) traffic is allowed.

2. **CloudWatch Log Issues**: Check IAM permissions and ensure the CloudWatch agent is running on the instance.

3. **Service Catalog Errors**: Verify that the Service Catalog launch role has appropriate permissions to create the resources.

For additional help, please contact the security team.