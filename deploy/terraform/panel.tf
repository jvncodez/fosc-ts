# Painel web atrás de API Gateway + Cognito (contrato: .kiro/steering/panel-proxy.md).
#
# Fase 1 (esta sessão): Cognito User Pool STANDALONE — login nativo
# usuário/senha do Cognito. Desvio documentado da tarefa 7 da spec
# aws-authorization (federação a IAM Identity Center), porque esta conta não
# tem Identity Center habilitado. Trocar por federação SAML/OIDC depois é só
# configuração do User Pool (identity provider), sem mudar o contrato do app.
#
# Caminho: Internet -> API Gateway HTTP (rotas / e /api/*, JWT authorizer do
# Cognito) -> VPC Link -> NLB interno -> serviço ECS Fargate do viewer
# (fosc.cli -v, modo proxy via SENTINELA_PUBLIC_ORIGIN). SSE (/api/events) é
# long-lived; API Gateway HTTP não tem o timeout de 29s do REST, mas o
# proxy_integration ainda corta por inatividade — ver nota em outputs.

# ---- Security group do viewer: só o NLB alcança a task -------------------------
resource "aws_security_group" "panel" {
  name = "${local.name}-panel"
  # ASCII puro: a API EC2 CreateSecurityGroup rejeita GroupDescription fora de ASCII.
  description = "Panel ingress - only from the internal NLB (VPC Link)."
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "panel_from_vpc" {
  # NLB não tem security group próprio; o ingress é restringido ao CIDR da VPC
  # (o NLB só é alcançável de dentro da VPC/VPC Link, nunca da internet direto).
  security_group_id = aws_security_group.panel.id
  description       = "HTTP do NLB interno (dentro da VPC)"
  ip_protocol       = "tcp"
  from_port         = var.panel_port
  to_port           = var.panel_port
  cidr_ipv4         = data.aws_vpc.selected.cidr_block
}

resource "aws_vpc_security_group_egress_rule" "panel_to_efs" {
  security_group_id            = aws_security_group.panel.id
  description                  = "NFS ao EFS (estado compartilhado com o worker)"
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  referenced_security_group_id = aws_security_group.efs.id
}

# O API Gateway VPC Link usa este SG nas ENIs de origem. Sem egress na porta do
# viewer, a integração retorna 503 embora o target do NLB esteja healthy.
resource "aws_vpc_security_group_egress_rule" "vpc_link_to_panel" {
  security_group_id = aws_security_group.panel.id
  description       = "API Gateway VPC Link to panel listener"
  ip_protocol       = "tcp"
  from_port         = var.panel_port
  to_port           = var.panel_port
  cidr_ipv4         = data.aws_vpc.selected.cidr_block
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_panel" {
  security_group_id            = aws_security_group.efs.id
  description                  = "NFS vindo do painel"
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  referenced_security_group_id = aws_security_group.panel.id
}

resource "aws_vpc_security_group_egress_rule" "panel_to_endpoints" {
  count                        = var.create_vpc_endpoints ? 1 : 0
  security_group_id            = aws_security_group.panel.id
  description                  = "HTTPS aos VPC endpoints (Bedrock/SQS/Secrets/Logs)"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.endpoints[0].id
}

resource "aws_vpc_security_group_egress_rule" "endpoints_from_panel" {
  count                        = var.create_vpc_endpoints ? 1 : 0
  security_group_id            = aws_security_group.endpoints[0].id
  description                  = "HTTPS vindo do painel"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.panel.id
}

# Pull da camada de imagem (blob grande) via ECR/S3: o Fargate faz streaming
# HTTP direto no S3 (httpReadSeeker), e isso não respeitou o S3 Gateway
# Endpoint nesta conta/VPC mesmo com rota e SG corretos para a task do worker
# (ver network.tf task_to_s3) - sintoma: "dial tcp <ip-do-prefix-list-s3>:443:
# i/o timeout" mesmo com assign_public_ip=true. Mesma regra aqui, replicada
# para o SG do painel.
resource "aws_vpc_security_group_egress_rule" "panel_to_s3" {
  count             = var.create_vpc_endpoints ? 1 : 0
  security_group_id = aws_security_group.panel.id
  description       = "HTTPS to S3 (ECR image layers) via gateway endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = data.aws_prefix_list.s3[0].id
}

resource "aws_vpc_security_group_egress_rule" "panel_https_fallback" {
  count             = var.create_vpc_endpoints ? 0 : 1
  security_group_id = aws_security_group.panel.id
  description       = "FALLBACK sem endpoints: HTTPS à internet (AWS APIs via NAT)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

# ---- NLB interno + target group (o que o VPC Link do API Gateway alcança) -----
resource "aws_lb" "panel" {
  name               = "${local.name}-panel"
  internal           = true
  load_balancer_type = "network"
  subnets            = var.private_subnet_ids
}

resource "aws_lb_target_group" "panel" {
  name        = "${local.name}-panel"
  port        = var.panel_port
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    protocol = "TCP"
    port     = tostring(var.panel_port)
  }
}

resource "aws_lb_listener" "panel" {
  load_balancer_arn = aws_lb.panel.arn
  port              = var.panel_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.panel.arn
  }
}

# ---- Serviço Fargate do viewer (painel) ----------------------------------------
resource "aws_ecs_task_definition" "panel" {
  family                   = "${local.name}-panel"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.panel_cpu
  memory                   = var.panel_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.panel.arn

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
      name      = "${local.name}-panel"
      image     = local.image
      essential = true
      command   = ["python3", "-m", "fosc.cli", "-v", "-p", tostring(var.panel_port)]

      portMappings = [{ containerPort = var.panel_port, protocol = "tcp" }]

      mountPoints = [{
        sourceVolume  = "sentinela-state"
        containerPath = "/data"
        readOnly      = false
      }]

      environment = [
        { name = "AWS_REGION", value = local.region },
        { name = "SENTINELA_HOME", value = "/data" },
        { name = "SENTINELA_PROVIDER", value = "bedrock" },
        { name = "SENTINELA_AUTHZ", value = "ask" },     # headless recusa yolo
        { name = "SENTINELA_SCOPE_PROXY", value = "1" }, # escopo na rede
        { name = "BEDROCK_SONNET", value = var.bedrock_sonnet },
        { name = "BEDROCK_OPUS", value = var.bedrock_opus },
        { name = "BEDROCK_HAIKU", value = var.bedrock_haiku },
        { name = "SENTINELA_SQS_URL", value = local.queue_url },
        { name = "SENTINELA_MAX_HUNTS", value = tostring(var.max_hunts) },
        # Liga o modo proxy no webview.py: bind 0.0.0.0, Host/Origin confiam no
        # API Gateway, autenticação é do Cognito no authorizer (não do viewer).
        { name = "SENTINELA_PUBLIC_ORIGIN", value = local.panel_public_origin },
        # Metadados OAuth publicos consumidos por GET /auth/config. O app client
        # e publico (sem secret); o browser usa Authorization Code + PKCE.
        { name = "SENTINELA_COGNITO_DOMAIN", value = local.cognito_domain },
        { name = "SENTINELA_COGNITO_USER_POOL_ID", value = aws_cognito_user_pool.panel.id },
        { name = "SENTINELA_COGNITO_CLIENT_ID", value = aws_cognito_user_pool_client.panel.id },
        { name = "SENTINELA_COGNITO_REDIRECT_URI", value = "${local.panel_public_origin}/" },
        { name = "SENTINELA_COGNITO_SCOPES", value = "openid profile email" },
      ]

      secrets = [
        { name = "TELEGRAM_TOKEN", valueFrom = "${local.secret_arn}:token::" },
        { name = "TELEGRAM_CHAT_ID", valueFrom = "${local.secret_arn}:chat_id::" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.panel.name
          "awslogs-region"        = local.region
          "awslogs-stream-prefix" = "panel"
        }
      }
    }
  ])
}

resource "aws_cloudwatch_log_group" "panel" {
  name              = "/ecs/${local.name}-panel"
  retention_in_days = 30
}

# ---- IAM do painel: mesmo contrato de menor privilégio do worker --------------
# Precisa ler RunState/approvals do EFS, publicar na fila (start_hunt) e invocar
# Bedrock só se o chat do painel usar o modelo diretamente. Sem permissão sobre
# o alvo (igual ao worker) — o escopo é de rede, não de IAM.
resource "aws_iam_role" "panel" {
  name               = "${local.name}-panel-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "panel_task" {
  statement {
    sid       = "BedrockInvokeApprovedModels"
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
    resources = concat(local.bedrock_foundation_arns, local.bedrock_profile_arns)
  }

  statement {
    sid       = "ReadTelegramSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["${aws_secretsmanager_secret.telegram.arn}*"]
  }

  statement {
    sid       = "MountPersistentState"
    effect    = "Allow"
    actions   = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]
    resources = [aws_efs_file_system.state.arn]
    condition {
      test     = "StringEquals"
      variable = "elasticfilesystem:AccessPointArn"
      values   = [aws_efs_access_point.state.arn]
    }
  }

  statement {
    sid    = "HuntQueueSQS"
    effect = "Allow"
    actions = [
      "sqs:SendMessage",
      "sqs:GetQueueAttributes",
    ]
    resources = [aws_sqs_queue.hunts.arn]
  }

  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.panel.arn}:*"]
  }
}

resource "aws_iam_role_policy" "panel_task" {
  name   = "${local.name}-panel-task"
  role   = aws_iam_role.panel.id
  policy = data.aws_iam_policy_document.panel_task.json
}

resource "aws_ecs_service" "panel" {
  name            = "${local.name}-panel"
  cluster         = aws_ecs_cluster.sentinela.id
  task_definition = aws_ecs_task_definition.panel.arn
  desired_count   = var.panel_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.panel.id]
    # Decisão registrada: o pull da camada de imagem (~1GB) via S3 Gateway
    # Endpoint travou (httpReadSeeker i/o timeout) mesmo com rota/SG corretos
    # (streaming de blob grande não respeitou o gateway endpoint nesta conta).
    # A subnet já é pública (workshop); dar IP público só ao PAINEL destrava o
    # pull via internet normal. O worker (aws_ecs_service.sentinela) continua
    # com assign_public_ip=var.assign_public_ip (false) — essa concessão é só
    # para a task do painel, cujo SG de ingress continua restrito ao NLB.
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.panel.arn
    container_name   = "${local.name}-panel"
    container_port   = var.panel_port
  }

  depends_on = [aws_lb_listener.panel]
}

# ---- Cognito User Pool STANDALONE (Fase 1 — sem Identity Center) --------------
resource "aws_cognito_user_pool" "panel" {
  name = "${local.name}-panel"

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }

  # Sem auto-cadastro público: só um admin (`aws cognito-idp admin-create-user`)
  # cria operadores — o painel autoriza ações sensíveis do agente, não é um
  # produto de autoatendimento.
  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  mfa_configuration = "OPTIONAL"
  software_token_mfa_configuration {
    enabled = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  auto_verified_attributes = ["email"]
}

resource "aws_cognito_user_pool_domain" "panel" {
  domain       = "${local.name}-${local.account_id}"
  user_pool_id = aws_cognito_user_pool.panel.id
}

# App client público (sem secret) — o viewer confia no JWT authorizer do API
# Gateway, nunca troca código/token ele mesmo neste modo (isso é exatamente o
# que o panel-proxy.md exige: autenticação é da camada do proxy).
resource "aws_cognito_user_pool_client" "panel" {
  name            = "${local.name}-panel"
  user_pool_id    = aws_cognito_user_pool.panel.id
  generate_secret = false

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  supported_identity_providers         = ["COGNITO"]

  callback_urls = ["${local.panel_public_origin}/"]
  logout_urls   = ["${local.panel_public_origin}/"]

  explicit_auth_flows = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

  access_token_validity  = 15
  id_token_validity      = 15
  refresh_token_validity = 1
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }
}

# ---- VPC Link (API Gateway -> NLB interno) -------------------------------------
resource "aws_apigatewayv2_vpc_link" "panel" {
  name               = "${local.name}-panel"
  security_group_ids = [aws_security_group.panel.id]
  subnet_ids         = var.private_subnet_ids
}

# ---- API Gateway HTTP + JWT authorizer (Cognito) -------------------------------
resource "aws_apigatewayv2_api" "panel" {
  name          = "${local.name}-panel"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "panel" {
  api_id              = aws_apigatewayv2_api.panel.id
  integration_type    = "HTTP_PROXY"
  integration_subtype = null
  integration_method  = "ANY"
  integration_uri     = aws_lb_listener.panel.arn
  connection_type     = "VPC_LINK"
  connection_id       = aws_apigatewayv2_vpc_link.panel.id
  request_parameters = {
    # Sobrescrever, nunca anexar: impede o cliente de falsificar a identidade.
    # Esta integração é usada somente por rotas protegidas pelo JWT authorizer.
    "overwrite:header.X-Operator" = "$context.authorizer.claims.sub"
  }
  # SSE (/api/events) é um stream longo. HTTP API não tem o teto de 29s do REST,
  # mas o timeout da integração ainda se aplica — ver panel-proxy.md item 5.
  timeout_milliseconds = 29000
}

# Bootstrap e assets estáticos não possuem JWT ainda e usam uma integração
# separada, sem X-Operator nem qualquer outro dado de contexto do authorizer.
resource "aws_apigatewayv2_integration" "panel_public" {
  api_id               = aws_apigatewayv2_api.panel.id
  integration_type     = "HTTP_PROXY"
  integration_subtype  = null
  integration_method   = "ANY"
  integration_uri      = aws_lb_listener.panel.arn
  connection_type      = "VPC_LINK"
  connection_id        = aws_apigatewayv2_vpc_link.panel.id
  timeout_milliseconds = 29000
}

resource "aws_apigatewayv2_authorizer" "panel" {
  api_id           = aws_apigatewayv2_api.panel.id
  name             = "${local.name}-cognito"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.panel.id]
    issuer   = "https://cognito-idp.${local.region}.amazonaws.com/${aws_cognito_user_pool.panel.id}"
  }
}

# O bootstrap da SPA e os assets estaticos sao publicos para o navegador poder
# iniciar Authorization Code + PKCE. Todo /api/* continua caindo no catch-all
# JWT abaixo; uma rota exata tem precedencia sobre /{proxy+}.
locals {
  panel_public_get_routes = toset([
    "/styles.css",
    "/tokens.css",
    "/features.css",
    "/terminal.css",
    "/assets/fosc-ts.svg",
    "/src/app.js",
    "/src/services/api.js",
    "/src/services/auth.js",
    "/auth/config",
  ])
}

resource "aws_apigatewayv2_route" "panel_public_assets" {
  for_each           = local.panel_public_get_routes
  api_id             = aws_apigatewayv2_api.panel.id
  route_key          = "GET ${each.value}"
  target             = "integrations/${aws_apigatewayv2_integration.panel_public.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "panel_all" {
  api_id               = aws_apigatewayv2_api.panel.id
  route_key            = "ANY /{proxy+}"
  target               = "integrations/${aws_apigatewayv2_integration.panel.id}"
  authorization_type   = "JWT"
  authorizer_id        = aws_apigatewayv2_authorizer.panel.id
  authorization_scopes = ["openid"]
}

resource "aws_apigatewayv2_route" "panel_root" {
  api_id             = aws_apigatewayv2_api.panel.id
  route_key          = "GET /"
  target             = "integrations/${aws_apigatewayv2_integration.panel_public.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_stage" "panel" {
  api_id      = aws_apigatewayv2_api.panel.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.panel_access.arn
    format = jsonencode({
      requestId        = "$context.requestId", ip = "$context.identity.sourceIp",
      routeKey         = "$context.routeKey", status = "$context.status",
      integrationError = "$context.integrationErrorMessage",
    })
  }
}

resource "aws_cloudwatch_log_group" "panel_access" {
  name              = "/apigw/${local.name}-panel"
  retention_in_days = 30
}

locals {
  # Sem domínio customizado (Fase 1): a própria URL do stage do API Gateway é
  # o SENTINELA_PUBLIC_ORIGIN. Trocar por CloudFront+domínio próprio depois é
  # só variável, sem mudar o contrato do viewer.
  panel_public_origin = "https://${aws_apigatewayv2_api.panel.id}.execute-api.${local.region}.amazonaws.com"
  cognito_domain      = "https://${aws_cognito_user_pool_domain.panel.domain}.auth.${local.region}.amazoncognito.com"
}
