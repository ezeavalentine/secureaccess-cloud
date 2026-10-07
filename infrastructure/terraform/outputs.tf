output "jit_orchestrator_role_arn" {
  value = aws_iam_role.jit_orchestrator.arn
}
output "dynamodb_audit_table_name" {
  value = aws_dynamodb_table.jit_audit_logs.name
}
output "cloudtrail_bucket_name" {
  value = var.enable_cloudtrail_logging ? aws_s3_bucket.cloudtrail_logs[0].id : null
}
output "jit_role_arns" {
  value = { for name, role in aws_iam_role.jit_target : name => role.arn
  }
}
output "revoker_role_arn" {
  value = aws_iam_role.revoker.arn
}
output "application_load_balancer" {
  value = var.deploy_application ? aws_lb.app[0].dns_name : null
}
