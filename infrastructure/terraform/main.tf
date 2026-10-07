terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0"
    }

  }
}
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = { Project = "SecureAccessCloud", Environment = var.environment, ManagedBy = "Terraform"
    }
  }
}
data "aws_caller_identity" "current" {}
locals {
  target_accounts      = length(var.target_account_ids) > 0 ? var.target_account_ids : [data.aws_caller_identity.current.account_id]
  trusted_orchestrator = var.trusted_orchestrator_arn != "" ? var.trusted_orchestrator_arn : aws_iam_role.jit_orchestrator.arn
  jit_roles = {
    ReadOnly = { duration = var.jit_max_duration_seconds, policy = "ReadOnlyAccess"
    }
    PowerUser = { duration = var.jit_max_duration_seconds, policy = "PowerUserAccess"
    }
    DBAdmin = { duration = var.jit_max_duration_seconds, policy = "AmazonRDSFullAccess"
    }
    AdministratorAccess = { duration = 3600, policy = "AdministratorAccess"
    }

  }
}
