# CloudWatch Logs do agente.
resource "aws_cloudwatch_log_group" "sentinela" {
  name              = "/ecs/${local.name}"
  retention_in_days = 30
}
