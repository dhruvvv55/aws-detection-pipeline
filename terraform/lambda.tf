locals {
  lambda_name    = "${var.project_name}-handler"
  lambda_timeout = 15
}

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/src"
  output_path = "${path.module}/build/lambda.zip"
  excludes    = ["__pycache__", "**/__pycache__", "**/__pycache__/**"]
}

# Created by Terraform so we control retention. If Lambda creates it,
# logs are kept forever and the role needs logs:CreateLogGroup.
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.lambda_name}"
  retention_in_days = 14
}

# ---------- IAM ----------

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.lambda_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# What every detection needs: read the queue, write logs, findings, alerts
data "aws_iam_policy_document" "lambda_base" {
  statement {
    sid = "ConsumeEventsQueue"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]
    resources = [aws_sqs_queue.events.arn]
  }

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid       = "WriteFindings"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.findings.arn]
  }

  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "lambda_base" {
  name   = "base"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_base.json
}

# Detection 1: only the two S3 calls it needs. Any bucket can be the victim,
# so the resource can't be narrowed further than arn:aws:s3:::*
data "aws_iam_policy_document" "detect_s3_public" {
  statement {
    sid = "S3PublicBucketRemediation"
    actions = [
      "s3:GetBucketTagging",           # allowlist check
      "s3:PutBucketPublicAccessBlock", # the fix
    ]
    resources = ["arn:aws:s3:::*"]
  }
}

resource "aws_iam_role_policy" "detect_s3_public" {
  name   = "detect-s3-public"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.detect_s3_public.json
}

# ---------- Function ----------

resource "aws_lambda_function" "handler" {
  function_name    = local.lambda_name
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = local.lambda_timeout
  memory_size      = 256

  environment {
    variables = {
      LOG_LEVEL       = "INFO"
      DRY_RUN         = tostring(var.dry_run)
      FINDINGS_TABLE  = aws_dynamodb_table.findings.name
      ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda_base,
    aws_iam_role_policy.detect_s3_public,
  ]
}

resource "aws_lambda_event_source_mapping" "events_queue" {
  event_source_arn = aws_sqs_queue.events.arn
  function_name    = aws_lambda_function.handler.arn
  batch_size       = 10

  # Lets the handler fail individual messages instead of the whole batch
  function_response_types = ["ReportBatchItemFailures"]

  depends_on = [aws_iam_role_policy.lambda_base]
}
