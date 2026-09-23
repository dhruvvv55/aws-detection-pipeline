output "account_id" {
  value = local.account_id
}

output "trail_name" {
  value = aws_cloudtrail.main.name
}

output "trail_bucket" {
  value = aws_s3_bucket.trail.id
}

output "events_queue_url" {
  value = aws_sqs_queue.events.id
}

output "dlq_url" {
  value = aws_sqs_queue.dlq.id
}

output "lambda_log_group" {
  value = aws_cloudwatch_log_group.lambda.name
}

output "findings_table" {
  value = aws_dynamodb_table.findings.name
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
