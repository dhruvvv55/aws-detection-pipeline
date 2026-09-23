variable "region" {
  description = "Home region. IAM is global and its CloudTrail events land in us-east-1, so everything runs here."
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile (IAM Identity Center / SSO)"
  type        = string
  default     = "detlab"
}

variable "project_name" {
  description = "Prefix for resource names"
  type        = string
  default     = "aws-detect-remediate"
}

variable "alert_email" {
  description = "Email for budget alerts (and later SNS findings)"
  type        = string
}

variable "budget_limit_usd" {
  description = "Monthly cost budget in USD"
  type        = string
  default     = "5"
}

variable "log_retention_days" {
  description = "Days to keep CloudTrail logs in S3 before expiry"
  type        = number
  default     = 30
}

variable "dry_run" {
  description = "If true, detect and alert but never remediate"
  type        = bool
  default     = false
}
