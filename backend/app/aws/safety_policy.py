"""Shared session restrictions. Target roles must carry this reviewed boundary."""
GLOBAL_DENIES = [
    "iam:*", "sts:AssumeRole*", "sts:GetFederationToken", "organizations:*",
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
    "ecs:*", "ecr:*", "lambda:*", "codebuild:*", "cloudformation:*",
    "ssm:SendCommand", "ssm:StartSession", "secretsmanager:GetSecretValue",
]


def safety_policy():
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": GLOBAL_DENIES, "Resource": "*"},
        {"Effect": "Deny", "Action": ["dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem", "dynamodb:DeleteTable", "dynamodb:UpdateTable"], "Resource": "arn:aws:dynamodb:*:*:table/secureaccess_audit_logs"},
        {"Effect": "Deny", "Action": ["s3:DeleteObject*", "s3:PutObject*", "s3:DeleteBucket*", "s3:PutBucket*", "s3:BypassGovernanceRetention"], "Resource": ["arn:aws:s3:::secureaccess-cloudtrail-*", "arn:aws:s3:::secureaccess-cloudtrail-*/*"]},
    ]}
