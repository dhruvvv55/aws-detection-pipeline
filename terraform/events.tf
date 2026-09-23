# CloudTrail management events show up on the default event bus as
# "AWS API Call via CloudTrail". EventBridge rules are regional, which is
# why everything lives in us-east-1 (where IAM's global events land).

resource "aws_cloudwatch_event_rule" "s3_public_access" {
  name        = "${var.project_name}-s3-public-access"
  description = "S3 bucket policy, ACL, and Block Public Access changes"

  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketPolicy",
        "PutBucketAcl",
        "DeleteBucketPublicAccessBlock",
        "PutBucketPublicAccessBlock", # setting BPA flags to false is just as bad as deleting it
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_public_access_to_sqs" {
  rule      = aws_cloudwatch_event_rule.s3_public_access.name
  target_id = "events-queue"
  arn       = aws_sqs_queue.events.arn
}
