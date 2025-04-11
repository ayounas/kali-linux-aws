#!/bin/bash
set -e

# Configuration
PORTFOLIO_NAME="Security Tools Portfolio"
PRODUCT_NAME="Kali Linux Security Instance"
PRODUCT_VERSION="1.0.0"
PRODUCT_DESCRIPTION="A Kali Linux instance for security operations with SSM integration, CloudWatch logging, and auto-termination"
TERRAFORM_DIR="../"
TEMPLATE_PATH="../service-catalog/template.yaml"

# Color for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "===== Kali Linux AWS Service Catalog Setup ====="
echo "This script will package and publish your Kali Linux solution to AWS Service Catalog."

# Check AWS CLI installation
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Check AWS credentials
echo "Verifying AWS credentials..."
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}Error: AWS credentials are not configured. Please run 'aws configure' first.${NC}"
    exit 1
fi

# Get AWS account and region information
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
if [ -z "$REGION" ]; then
    echo -e "${RED}Error: AWS region is not configured. Please run 'aws configure' first.${NC}"
    exit 1
fi

echo "Using AWS Account: $ACCOUNT_ID in Region: $REGION"

# Create S3 bucket for artifacts if it doesn't exist
BUCKET_NAME="service-catalog-artifacts-${ACCOUNT_ID}-${REGION}"
S3_KEY="kali-linux-aws/${PRODUCT_VERSION}/terraform.zip"

echo "Creating/verifying S3 bucket for artifacts..."
if ! aws s3api head-bucket --bucket "${BUCKET_NAME}" 2>/dev/null; then
    echo "Creating S3 bucket: s3://${BUCKET_NAME}"
    if [ "$REGION" = "us-east-1" ]; then
        aws s3 mb "s3://${BUCKET_NAME}" --region "${REGION}"
    else
        aws s3 mb "s3://${BUCKET_NAME}" --region "${REGION}" --create-bucket-configuration LocationConstraint="${REGION}"
    fi
    
    # Enable versioning on the bucket
    aws s3api put-bucket-versioning --bucket "${BUCKET_NAME}" --versioning-configuration Status=Enabled
    
    # Block public access to the bucket
    aws s3api put-public-access-block --bucket "${BUCKET_NAME}" \
        --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
else
    echo "S3 bucket already exists: s3://${BUCKET_NAME}"
fi

# Create a temporary directory and zip the Terraform files
echo "Packaging Terraform code..."
TEMP_DIR=$(mktemp -d)
ZIP_FILE="${TEMP_DIR}/terraform.zip"

# Copy Terraform files to a temporary directory
cp -R "${TERRAFORM_DIR}"/* "${TEMP_DIR}/"

# Remove any temporary or unnecessary files
rm -rf "${TEMP_DIR}/.git" "${TEMP_DIR}/.terraform" "${TEMP_DIR}/.terraform.lock.hcl" "${TEMP_DIR}/terraform.tfstate*"
find "${TEMP_DIR}" -name "*.zip" -delete

# Create a basic README file
cat > "${TEMP_DIR}/README.md" << EOF
# Kali Linux AWS Deployment

This package deploys a Kali Linux instance in AWS with:
- SSM integration for remote access
- CloudWatch logging for forensic capabilities
- Auto-termination after specified time
- Persistent log storage

## Accessing the Instance

The instance is accessible through AWS Systems Manager (SSM) in Fleet Manager.
No direct SSH access is required.

## Auto-Termination

The instance will be automatically terminated after the configured hours.
All logs will be preserved in CloudWatch.
EOF

# Create a variables.auto.tfvars template
cat > "${TEMP_DIR}/terraform.tfvars.template" << EOF
# AWS Region for deployment
aws_region = "eu-west-2"

# Network configuration
vpc_id    = "vpc-xxxxxxxx"
subnet_id = "subnet-xxxxxxxx"
private_ip = null  # Optional: Specify a static private IP

# Instance configuration
instance_type = "t3.medium"
root_volume_size = 30
key_name = null  # Optional: Specify SSH key name if needed

# Auto-termination (in hours, 24h = 1 day)
auto_termination_time = 24

# Resource naming
name_prefix = "kali"
environment = "security"
EOF

# Create zip file with all Terraform code
cd "${TEMP_DIR}" && zip -r "${ZIP_FILE}" ./* > /dev/null
cd - > /dev/null

# Upload the zip file to S3
echo "Uploading Terraform code to S3..."
aws s3 cp "${ZIP_FILE}" "s3://${BUCKET_NAME}/${S3_KEY}"

# Upload the CloudFormation template to S3
echo "Uploading CloudFormation template to S3..."
TEMPLATE_S3_KEY="kali-linux-aws/${PRODUCT_VERSION}/template.yaml"
aws s3 cp "${TEMPLATE_PATH}" "s3://${BUCKET_NAME}/${TEMPLATE_S3_KEY}"

# Clean up the temporary directory
rm -rf "${TEMP_DIR}"

# Check if portfolio exists, create if it doesn't
echo "Creating/retrieving portfolio..."
PORTFOLIO_ID=$(aws servicecatalog list-portfolios --query "PortfolioDetails[?DisplayName=='${PORTFOLIO_NAME}'].Id" --output text)

if [ -z "${PORTFOLIO_ID}" ]; then
    echo "Creating new portfolio..."
    PORTFOLIO_ID=$(aws servicecatalog create-portfolio \
        --display-name "${PORTFOLIO_NAME}" \
        --description "Portfolio containing security tools and resources" \
        --provider-name "Security Team" \
        --query "PortfolioDetail.Id" \
        --output text)
    echo "Portfolio created with ID: ${PORTFOLIO_ID}"
else
    echo "Portfolio already exists with ID: ${PORTFOLIO_ID}"
fi

# Check if product exists, create if it doesn't
echo "Creating/retrieving product..."
PRODUCT_ID=$(aws servicecatalog search-products-as-admin \
    --filters "FullTextSearch=${PRODUCT_NAME}" \
    --query "ProductViewDetails[?ProductViewSummary.Name=='${PRODUCT_NAME}'].ProductViewSummary.ProductId" \
    --output text)

if [ -z "${PRODUCT_ID}" ]; then
    echo "Creating new product..."
    PRODUCT_ID=$(aws servicecatalog create-product \
        --name "${PRODUCT_NAME}" \
        --owner "Security Team" \
        --description "${PRODUCT_DESCRIPTION}" \
        --distributor "Security Team" \
        --support-description "Please contact the security team for support" \
        --support-email "security@example.com" \
        --support-url "https://wiki.example.com/security/kali-linux" \
        --product-type "CLOUD_FORMATION_TEMPLATE" \
        --provisioning-artifact-parameters "Name=${PRODUCT_VERSION},Description=Initial version,Info={LoadTemplateFromURL=s3://${BUCKET_NAME}/${TEMPLATE_S3_KEY}},Type=CLOUD_FORMATION_TEMPLATE" \
        --query "ProductViewDetail.ProductViewSummary.ProductId" \
        --output text)
    
    echo "Product created with ID: ${PRODUCT_ID}"
    
    echo "Associating product with portfolio..."
    aws servicecatalog associate-product-with-portfolio \
        --product-id "${PRODUCT_ID}" \
        --portfolio-id "${PORTFOLIO_ID}"
else
    echo "Product already exists with ID: ${PRODUCT_ID}"
    
    # Create new version
    echo "Adding new version ${PRODUCT_VERSION} to existing product..."
    aws servicecatalog create-provisioning-artifact \
        --product-id "${PRODUCT_ID}" \
        --parameters "Name=${PRODUCT_VERSION},Description=Updated version,Info={LoadTemplateFromURL=s3://${BUCKET_NAME}/${TEMPLATE_S3_KEY}},Type=CLOUD_FORMATION_TEMPLATE" \
        --idempotency-token "update-$(date +%s)"
fi

# Create launch constraint (IAM role for Service Catalog to use)
echo "Setting up Service Catalog launch role..."
ROLE_NAME="KaliLinuxServiceCatalogRole"
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

# Check if role exists
if ! aws iam get-role --role-name "${ROLE_NAME}" &> /dev/null; then
    echo "Creating IAM role for Service Catalog..."
    aws iam create-role \
        --role-name "${ROLE_NAME}" \
        --assume-role-policy-document '{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "servicecatalog.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }'
    
    # Attach AdministratorAccess policy (Note: In production you would want to scope this down)
    aws iam attach-role-policy \
        --role-name "${ROLE_NAME}" \
        --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"
    
    # Allow time for the role to propagate
    echo "Waiting for the role to propagate..."
    sleep 10
fi

# Associate the launch constraint with the portfolio and product
echo "Setting up launch constraint..."
aws servicecatalog create-constraint \
    --portfolio-id "${PORTFOLIO_ID}" \
    --product-id "${PRODUCT_ID}" \
    --type "LAUNCH" \
    --parameters "{\"RoleArn\":\"${ROLE_ARN}\"}" \
    --description "Launch constraint for Kali Linux using Service Catalog role"

# Grant access to the current user
echo "Granting access to the current user..."
CURRENT_USER_ARN=$(aws sts get-caller-identity --query Arn --output text)

aws servicecatalog associate-principal-with-portfolio \
    --portfolio-id "${PORTFOLIO_ID}" \
    --principal-arn "${CURRENT_USER_ARN}" \
    --principal-type "IAM" 

echo -e "${GREEN}Setup completed successfully!${NC}"
echo "Portfolio ID: ${PORTFOLIO_ID}"
echo "Product ID: ${PRODUCT_ID}"
echo ""
echo "Your Kali Linux solution is now available in AWS Service Catalog."
echo "Users can access it at: https://console.aws.amazon.com/servicecatalog/home?region=${REGION}#/products"