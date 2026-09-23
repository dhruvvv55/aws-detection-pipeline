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

# IAM is a global service, but its CloudTrail events are delivered to
# us-east-1. A rule in any other region would never see these.
resource "aws_cloudwatch_event_rule" "iam_privesc" {
  name        = "${var.project_name}-iam-privesc"
  description = "IAM changes that can grant admin access or new credentials"

  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
        "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
        "CreateAccessKey", "AddUserToGroup",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "iam_privesc_to_sqs" {
  rule      = aws_cloudwatch_event_rule.iam_privesc.name
  target_id = "events-queue"
  arn       = aws_sqs_queue.events.arn
}

# EC2 is regional, so this only sees security group changes in us-east-1.
# Covering other regions means forwarding their events to this bus (see README).
resource "aws_cloudwatch_event_rule" "sg_open" {
  name        = "${var.project_name}-sg-open"
  description = "Security group ingress rules added"

  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sg_open_to_sqs" {
  rule      = aws_cloudwatch_event_rule.sg_open.name
  target_id = "events-queue"
  arn       = aws_sqs_queue.events.arn
}
