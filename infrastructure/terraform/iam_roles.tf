resource "aws_iam_role" "jit_orchestrator" {
  name = "SecureAccessOrchestratorRole"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com"
    }, Action = "sts:AssumeRole"
    }]
  })
}
resource "aws_iam_role_policy" "jit_executor" {
  name = "SecureAccessExecutor"
  role = aws_iam_role.jit_orchestrator.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"], Resource = [for id in local.target_accounts : "arn:aws:iam::${id}:role/JIT-Access-*"], Condition = { StringEquals = { "aws:RequestTag/ManagedBy" = "SecureAccessCloud", "sts:ExternalId" = var.external_id
      }
      }
    },
    { Effect = "Allow", Action = "sts:AssumeRole", Resource = [for id in local.target_accounts : "arn:aws:iam::${id}:role/SecureAccessRevokerRole"], Condition = { StringEquals = { "sts:ExternalId" = var.external_id
      }
      }
    },
    { Effect = "Allow", Action = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Scan"], Resource = aws_dynamodb_table.jit_audit_logs.arn
    }
    ]
  })
}
resource "aws_iam_policy" "jit_boundary" {
  name = "SecureAccessJITBoundary"
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = "*", Resource = "*"
    },
    { Effect = "Deny", Action = ["iam:*", "sts:AssumeRole*", "sts:GetFederationToken", "organizations:*", "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"], Resource = "*"
    },
    { Effect = "Deny", Action = ["dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem", "dynamodb:DeleteTable", "dynamodb:UpdateTable"], Resource = "arn:aws:dynamodb:*:*:table/secureaccess_audit_logs"
    },
    { Effect = "Deny", Action = ["s3:DeleteObject*", "s3:PutObject*", "s3:DeleteBucket*", "s3:PutBucket*", "s3:BypassGovernanceRetention"], Resource = ["arn:aws:s3:::secureaccess-cloudtrail-*", "arn:aws:s3:::secureaccess-cloudtrail-*/*"]
    },
    { Effect = "Deny", Action = ["ecs:*", "ecr:*", "lambda:*", "codebuild:*", "cloudformation:*", "ssm:SendCommand", "ssm:StartSession", "secretsmanager:GetSecretValue"], Resource = "*"
    }
    ]
  })
}
resource "aws_iam_role" "jit_target" {
  for_each             = local.jit_roles
  name                 = "JIT-Access-${each.key}"
  max_session_duration = each.value.duration
  permissions_boundary = aws_iam_policy.jit_boundary.arn
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { AWS = local.trusted_orchestrator
    }, Action = ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"], Condition = { StringEquals = { "sts:ExternalId" = var.external_id, "aws:RequestTag/ManagedBy" = "SecureAccessCloud"
    }
    }
    }]
  })
}
resource "aws_iam_role_policy_attachment" "jit_target" {
  for_each   = local.jit_roles
  role       = aws_iam_role.jit_target[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/${each.value.policy}"
}
resource "aws_iam_role_policy" "db_dynamodb" {
  name = "DynamoDBMaintenance"
  role = aws_iam_role.jit_target["DBAdmin"].name
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["dynamodb:Describe*", "dynamodb:List*", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"], Resource = "*"
    }]
  })
}
resource "aws_iam_role" "revoker" {
  name = "SecureAccessRevokerRole"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { AWS = local.trusted_orchestrator
    }, Action = "sts:AssumeRole", Condition = { StringEquals = { "sts:ExternalId" = var.external_id
    }
    }
    }]
  })
}
resource "aws_iam_role_policy" "revoker" {
  name = "RevocationAndTrailLookup"
  role = aws_iam_role.revoker.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRole"], Resource = [for role in aws_iam_role.jit_target : role.arn]
    },
    { Effect = "Allow", Action = ["iam:GetPolicy", "iam:GetPolicyVersion"], Resource = aws_iam_policy.jit_boundary.arn },
    { Effect = "Allow", Action = "cloudtrail:LookupEvents", Resource = "*"
    }
    ]
  })
}
