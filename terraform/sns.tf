resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
}

# AWS emails a confirmation link after apply. No alerts arrive until you click it.
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
