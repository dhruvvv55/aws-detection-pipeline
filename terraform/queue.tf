locals {
  # Every detection rule that feeds the queue. Add new rules here.
  detection_rule_arns = [
    aws_cloudwatch_event_rule.s3_public_access.arn,
    aws_cloudwatch_event_rule.iam_privesc.arn,
    aws_cloudwatch_event_rule.sg_open.arn,
  ]
}

# Dead-letter queue: anything the Lambda fails on 3 times ends up here
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.project_name}-dlq"
  message_retention_seconds = 1209600 # 14 days, the max
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "events" {
  name                      = "${var.project_name}-events"
  message_retention_seconds = 345600 # 4 days
  sqs_managed_sse_enabled   = true

  # Must be at least the Lambda timeout, or a message becomes visible again
  # while the first invocation is still working on it. AWS recommends 6x.
  visibility_timeout_seconds = local.lambda_timeout * 6

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 3
  })
}

# Only our main queue may redrive into the DLQ
resource "aws_sqs_queue_redrive_allow_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.events.arn]
  })
}

data "aws_iam_policy_document" "events_queue" {
  statement {
    sid       = "AllowDetectionRules"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.events.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = local.detection_rule_arns
    }
  }

  # The Lambda can now detach policies from any IAM principal. If anyone with
  # sqs:SendMessage could drop a forged "AdministratorAccess attached" event in
  # the queue, they could make it strip a real admin's access. This Deny blocks
  # every sender except our EventBridge rules, even IAM users whose own policies
  # allow SendMessage. (aws:SourceArn is absent for normal callers, so the
  # negated condition matches and the Deny applies.)
  statement {
    sid       = "DenyEveryoneElse"
    effect    = "Deny"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.events.arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:SourceArn"
      values   = local.detection_rule_arns
    }
  }
}

resource "aws_sqs_queue_policy" "events" {
  queue_url = aws_sqs_queue.events.id
  policy    = data.aws_iam_policy_document.events_queue.json
}
