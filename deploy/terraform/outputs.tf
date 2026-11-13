output "ecr_repository_url" {
  description = "URL do repo ECR p/ docker push."
  value       = aws_ecr_repository.sentinela.repository_url
}

output "sqs_queue_url" {
  description = "URL da fila FIFO (env SENTINELA_SQS_URL)."
  value       = aws_sqs_queue.hunts.url
}

output "sqs_dlq_url" {
  value = aws_sqs_queue.hunts_dlq.url
}

output "efs_file_system_id" {
  value = aws_efs_file_system.state.id
}

output "telegram_secret_arn" {
  description = "Preencha token/chat_id neste segredo se passou vazios."
  value       = aws_secretsmanager_secret.telegram.arn
}

output "task_role_arn" {
  value = aws_iam_role.task.arn
}

output "execution_role_arn" {
  value = aws_iam_role.execution.arn
}

output "cluster_name" {
  value = aws_ecs_cluster.sentinela.name
}

output "task_definition" {
  value = aws_ecs_task_definition.sentinela.family
}

# Comando pronto p/ uma campanha avulsa (sem usar o serviço).
output "run_task_command" {
  description = "Rodar uma campanha única na Fargate."
  value = join(" ", [
    "aws ecs run-task",
    "--cluster ${aws_ecs_cluster.sentinela.name}",
    "--launch-type FARGATE",
    "--task-definition ${aws_ecs_task_definition.sentinela.family}",
    "--region ${local.region}",
    "--network-configuration 'awsvpcConfiguration={subnets=[${join(",", var.private_subnet_ids)}],securityGroups=[${aws_security_group.task.id}],assignPublicIp=${var.assign_public_ip ? "ENABLED" : "DISABLED"}}'",
  ])
}

# Login no ECR p/ o push da imagem.
output "ecr_login_command" {
  value = "aws ecr get-login-password --region ${local.region} | docker login --username AWS --password-stdin ${local.account_id}.dkr.ecr.${local.region}.amazonaws.com"
}

# ---- Painel (Fase 1) ------------------------------------------------------------
output "panel_url" {
  description = "URL pública do painel (API Gateway, sem domínio customizado)."
  value       = local.panel_public_origin
}

output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.panel.id
}

output "cognito_app_client_id" {
  value = aws_cognito_user_pool_client.panel.id
}

output "cognito_hosted_ui_domain" {
  description = "Domínio do Cognito Hosted UI (login)."
  value       = "https://${aws_cognito_user_pool_domain.panel.domain}.auth.${local.region}.amazoncognito.com"
}

output "cognito_create_operator_command" {
  description = "Cria o primeiro operador (login nativo Cognito, sem auto-cadastro)."
  value = join(" ", [
    "aws cognito-idp admin-create-user",
    "--user-pool-id ${aws_cognito_user_pool.panel.id}",
    "--username <email-do-operador>",
    "--user-attributes Name=email,Value=<email-do-operador> Name=email_verified,Value=true",
    "--region ${local.region}",
  ])
}

output "panel_cluster_service" {
  value = aws_ecs_service.panel.name
}
