# Rede: contenção de egress em camadas (steering .kiro/steering/deploy.md).
#
#   Camada de rede (esta) + proxy HTTP de escopo (G0, no container) + fila
#   determinística (recon). O egress da task é fechado: só os IPs do ALVO em
#   80/443, mais os serviços AWS via VPC endpoints (sem internet geral). Isso
#   contém nmap/masscan (TCP cru, que escapa do proxy HTTP).

# ---- Security groups -----------------------------------------------------------
resource "aws_security_group" "task" {
  name        = "${local.name}-task"
  description = "Egress da task Fargate — fechado ao alvo autorizado + AWS endpoints."
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "efs" {
  name        = "${local.name}-efs"
  description = "NFS do EFS — só a task monta."
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "endpoints" {
  count       = var.create_vpc_endpoints ? 1 : 0
  name        = "${local.name}-vpce"
  description = "HTTPS dos VPC endpoints — só a task chama."
  vpc_id      = var.vpc_id
}

# task -> EFS (NFS 2049)
resource "aws_vpc_security_group_egress_rule" "task_to_efs" {
  security_group_id            = aws_security_group.task.id
  description                  = "NFS ao EFS"
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  referenced_security_group_id = aws_security_group.efs.id
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_task" {
  security_group_id            = aws_security_group.efs.id
  description                  = "NFS vindo da task"
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  referenced_security_group_id = aws_security_group.task.id
}

# task -> alvo autorizado (80 e 443) — a contenção de rede do pentest
resource "aws_vpc_security_group_egress_rule" "task_to_target_https" {
  for_each          = toset(var.allowed_target_cidrs)
  security_group_id = aws_security_group.task.id
  description       = "HTTPS ao alvo autorizado"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "task_to_target_http" {
  for_each          = toset(var.allowed_target_cidrs)
  security_group_id = aws_security_group.task.id
  description       = "HTTP ao alvo autorizado"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = each.value
}

# task -> VPC endpoints (443) quando usamos endpoints
resource "aws_vpc_security_group_egress_rule" "task_to_endpoints" {
  count                        = var.create_vpc_endpoints ? 1 : 0
  security_group_id            = aws_security_group.task.id
  description                  = "HTTPS aos VPC endpoints da AWS"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.endpoints[0].id
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_task" {
  count                        = var.create_vpc_endpoints ? 1 : 0
  security_group_id            = aws_security_group.endpoints[0].id
  description                  = "HTTPS vindo da task"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.task.id
}

# task -> S3 (gateway endpoint, prefix list) p/ puxar camadas de imagem do ECR
data "aws_prefix_list" "s3" {
  count = var.create_vpc_endpoints ? 1 : 0
  name  = "com.amazonaws.${local.region}.s3"
}

resource "aws_vpc_security_group_egress_rule" "task_to_s3" {
  count             = var.create_vpc_endpoints ? 1 : 0
  security_group_id = aws_security_group.task.id
  description       = "HTTPS ao S3 (camadas ECR) via gateway endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = data.aws_prefix_list.s3[0].id
}

# FALLBACK sem endpoints: 443 à internet (precisa de NAT). Menos estrito — só
# use se não puder criar endpoints. O egress não-HTTP continua fechado ao alvo.
resource "aws_vpc_security_group_egress_rule" "task_https_internet" {
  count             = var.create_vpc_endpoints ? 0 : 1
  security_group_id = aws_security_group.task.id
  description       = "FALLBACK: HTTPS à internet (AWS APIs via NAT)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

# ---- VPC endpoints (egress fechado sem internet geral) -------------------------
locals {
  interface_endpoints = var.create_vpc_endpoints ? toset([
    "bedrock-runtime",
    "sqs",
    "secretsmanager",
    "ecr.api",
    "ecr.dkr",
    "logs",
    "sts",
  ]) : toset([])
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interface_endpoints
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${local.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
}

data "aws_route_tables" "vpc" {
  count  = var.create_vpc_endpoints ? 1 : 0
  vpc_id = var.vpc_id
}

resource "aws_vpc_endpoint" "s3" {
  count             = var.create_vpc_endpoints ? 1 : 0
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${local.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = data.aws_route_tables.vpc[0].ids
}
