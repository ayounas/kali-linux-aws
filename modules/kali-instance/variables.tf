variable "vpc_id" {
  description = "The VPC ID where the Kali instance will be deployed"
  type        = string
}

variable "subnet_id" {
  description = "The subnet ID where the Kali instance will be deployed"
  type        = string
}

variable "private_ip" {
  description = "The private IP address to assign to the instance. If not specified, a random IP from the subnet will be assigned"
  type        = string
  default     = null
}

variable "instance_type" {
  description = "The EC2 instance type for Kali Linux"
  type        = string
  default     = "t3.medium"
}

variable "key_name" {
  description = "The key pair name to use for SSH access"
  type        = string
  default     = null
}

variable "environment" {
  description = "Environment name for tagging resources"
  type        = string
  default     = "security"
}

variable "name_prefix" {
  description = "Prefix to be used in resource naming"
  type        = string
  default     = "kali"
}

variable "root_volume_size" {
  description = "Size of the root volume in GB"
  type        = number
  default     = 30
}

variable "root_volume_type" {
  description = "Type of the root volume (gp3, gp2, io1, etc.)"
  type        = string
  default     = "gp3"
}

variable "auto_termination_time" {
  description = "Time in hours after which the instance will be automatically terminated (mandatory)"
  type        = number
}

variable "additional_tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "enable_lambda_code_signing" {
  description = "Whether to enable Lambda code signing"
  type        = bool
  default     = false
}

variable "lambda_signing_profile_version_arns" {
  description = "List of ARNs for Lambda code signing profile versions"
  type        = list(string)
  default     = []
}