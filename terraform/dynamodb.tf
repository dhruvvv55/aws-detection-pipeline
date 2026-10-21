resource "aws_dynamodb_table" "findings" {
  #checkov:skip=CKV_AWS_119:Encrypted at rest by default with an AWS owned key; a CMK is not needed for this lab
  name         = "${var.project_name}-findings"
  billing_mode = "PAY_PER_REQUEST" # no idle cost, fine for bursty security events
  hash_key     = "finding_id"      # "<detection>#<CloudTrail eventID>", which makes writes idempotent

  attribute {
    name = "finding_id"
    type = "S"
  }

  # Findings are the audit trail of every automated change, so keep backups
  point_in_time_recovery {
    enabled = true
  }
}
