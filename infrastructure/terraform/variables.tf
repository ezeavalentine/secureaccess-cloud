variable "aws_region" {
  type    = string
  default = "us-east-1"
}
variable "environment" {
  type    = string
  default = "production"
}
variable "jit_max_duration_seconds" {
  type    = number
  default = 3600
  validation {
    condition     = var.jit_max_duration_seconds == 3600
    error_message = "The ECS broker uses role chaining, which caps live sessions at 3600 seconds."
  }
}
variable "enable_cloudtrail_logging" {
  type    = bool
  default = true
}
variable "external_id" {
  type        = string
  sensitive   = true
  description = "Unique external ID shared between broker configuration and target trusts"
  validation {
    condition     = length(var.external_id) >= 24
    error_message = "Provide a random external ID of at least 24 characters."
  }
}
variable "trusted_orchestrator_arn" {
  type        = string
  default     = ""
  description = "For target accounts, ARN of the orchestrator in the broker account; empty uses the local orchestrator"
}
variable "target_account_ids" {
  type        = list(string)
  default     = []
  description = "Explicit target-account allowlist; empty means this account only"
}
variable "audit_retention_days" {
  type    = number
  default = 365
}
variable "deploy_application" {
  type    = bool
  default = false
}
variable "vpc_id" {
  type    = string
  default = ""
}
variable "public_subnet_ids" {
  type    = list(string)
  default = []
}
variable "private_subnet_ids" {
  type    = list(string)
  default = []
}
variable "certificate_arn" {
  type    = string
  default = ""
}
variable "public_url" {
  type    = string
  default = ""
}
variable "backend_image" {
  type    = string
  default = ""
}
variable "frontend_image" {
  type    = string
  default = ""
}
variable "application_secret_arn" {
  type        = string
  default     = ""
  description = "Secrets Manager JSON containing SECRET_KEY, ENCRYPTION_KEY, AUDIT_HMAC_KEY, DATABASE_URL (durable PostgreSQL), AWS_EXTERNAL_ID, AWS_ACCOUNTS_JSON"
}

variable "optional_secret_keys" {
  type        = list(string)
  default     = []
  description = "Optional configured keys in the application secret: OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_DISCOVERY_URL, JIRA_URL, JIRA_USERNAME, JIRA_TOKEN, SERVICENOW_URL, SERVICENOW_USERNAME, SERVICENOW_PASSWORD, SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM."
  validation {
    condition     = alltrue([for key in var.optional_secret_keys : contains(["OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_DISCOVERY_URL", "JIRA_URL", "JIRA_USERNAME", "JIRA_TOKEN", "SERVICENOW_URL", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD", "SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM"], key)])
    error_message = "Optional secret keys must be supported identity, ticket, or SMTP settings."
  }
}

variable "ticket_verification_required" {
  type    = bool
  default = true
}

variable "kms_secret_key_arn" {
  type        = string
  default     = ""
  description = "Customer-managed KMS key used by the application secret, if applicable."
}
