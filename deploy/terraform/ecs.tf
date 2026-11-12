# Cluster, task definition e serviço (worker da fila SQS).

resource "aws_ecs_cluster" "sentinela" {
  name = local.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

locals {
  image      = "${aws_ecr_repository.sentinela.repository_url}:${var.image_tag}"
  queue_url  = aws_sqs_queue.hunts.url
  secret_arn = aws_secretsmanager_secret.telegram.arn
}

resource "aws_ecs_task_definition" "sentinela" {
  family                   = local.name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    cpu_architecture        = "X86_64"
    operating_system_family = "LINUX"
  }

  volume {
    name = "sentinela-state"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.state.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.state.id
        iam             = "ENABLED"
      }
    }
  }

  container_definitions = jsonencode([
    {
      name      = local.name
      image     = local.image
      essential = true

      mountPoints = [{
        sourceVolume  = "sentinela-state"
        containerPath = "/data"
        readOnly      = false
      }]

      environment = [
        { name = "AWS_REGION", value = local.region },
        { name = "SENTINELA_HOME", value = "/data" },
        { name = "SENTINELA_PROVIDER", value = "bedrock" },
        { name = "SENTINELA_AUTHZ", value = "ask" },        # headless recusa yolo
        { name = "SENTINELA_SCOPE_PROXY", value = "1" },    # escopo na rede
        { name = "CLAUDE_CODE_USE_BEDROCK", value = "1" },
        { name = "BEDROCK_SONNET", value = var.bedrock_sonnet },
        { name = "BEDROCK_OPUS", value = var.bedrock_opus },
        { name = "BEDROCK_HAIKU", value = var.bedrock_haiku },
        { name = "TARGET", value = var.target_url },
        { name = "FOSC_ARGS", value = var.fosc_args },
        { name = "SENTINELA_SQS_URL", value = local.queue_url },
        { name = "SENTINELA_MAX_HUNTS", value = tostring(var.max_hunts) },
      ]

      secrets = [
        { name = "TELEGRAM_TOKEN", valueFrom = "${local.secret_arn}:token::" },
        { name = "TELEGRAM_CHAT_ID", valueFrom = "${local.secret_arn}:chat_id::" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.sentinela.name
          "awslogs-region"        = local.region
          "awslogs-stream-prefix" = "sentinela"
        }
      }
    }
  ])
}

# Serviço = worker contínuo da fila. desired_count=0 por padrão (nada roda até
# você subir), evitando custo surpresa. Para uma campanha avulsa, use o comando
# `aws ecs run-task` do output em vez do serviço.
resource "aws_ecs_service" "sentinela" {
  name            = local.name
  cluster         = aws_ecs_cluster.sentinela.id
  task_definition = aws_ecs_task_definition.sentinela.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = var.assign_public_ip
  }

  lifecycle {
    ignore_changes = [desired_count] # escale pelo console/CLI sem conflitar com o TF
  }
}
