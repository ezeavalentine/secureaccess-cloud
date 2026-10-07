resource "aws_dynamodb_table" "jit_audit_logs" {
  name                        = "secureaccess_audit_logs"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "event_id"
  range_key                   = "timestamp"
  deletion_protection_enabled = true
  attribute {
    name = "event_id"
    type = "S"
  }
  attribute {
    name = "timestamp"
    type = "S"
  }
  attribute {
    name = "actor"
    type = "S"
  }
  global_secondary_index {
    name            = "ActorIndex"
    hash_key        = "actor"
    range_key       = "timestamp"
    projection_type = "ALL"
  }
  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }
  lifecycle {
    prevent_destroy = true
  }
}
