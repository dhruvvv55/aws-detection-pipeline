resource "aws_dynamodb_table" "findings" {
  name         = "${var.project_name}-findings"
  billing_mode = "PAY_PER_REQUEST" # no idle cost, fine for bursty security events
  hash_key     = "finding_id"      # "<detection>#<CloudTrail eventID>", which makes writes idempotent

  attribute {
    name = "finding_id"
    type = "S"
  }
}
