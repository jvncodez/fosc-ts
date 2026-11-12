# BB-Sentinela — entradas do módulo. Troque os <...> em terraform.tfvars.

variable "aws_region" {
  description = "Região AWS onde o Bedrock está habilitado e o stack roda."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefixo de nomes de todos os recursos."
  type        = string
  default     = "bb-sentinela"
}

# --- Rede (VPC existente; o módulo NÃO cria VPC) --------------------------------
variable "vpc_id" {
  description = "VPC existente onde a task e o EFS vivem."
  type        = string
}

variable "private_subnet_ids" {
  description = "Subnets (de preferência privadas) p/ a task, mount targets do EFS e endpoints."
  type        = list(string)
}

variable "assign_public_ip" {
  description = "Dar IP público à task (true só se usar subnet pública sem NAT/endpoints)."
  type        = bool
  default     = false
}

variable "create_vpc_endpoints" {
  description = "Criar VPC endpoints (Bedrock/SQS/Secrets/ECR/Logs/STS/S3) p/ egress fechado sem internet geral. Recomendado: true."
  type        = bool
  default     = true
}

# --- Escopo de rede (contenção do alvo, não-HTTP) -------------------------------
variable "allowed_target_cidrs" {
  description = "CIDRs do ALVO AUTORIZADO. O egress da task para 80/443 é liberado SÓ para estes. Camada de firewall p/ nmap/masscan (TCP cru que escapa do proxy HTTP)."
  type        = list(string)
  # ex.: ["44.227.89.148/32"]  — o IP do alvo autorizado
}

# --- Imagem ---------------------------------------------------------------------
variable "image_tag" {
  description = "Tag da imagem no ECR."
  type        = string
  default     = "latest"
}

# --- Contrato do container ------------------------------------------------------
variable "target_url" {
  description = "URL do escopo autorizado (env TARGET)."
  type        = string
  default     = "https://1.migbot.com.br/#/"
}

variable "fosc_args" {
  description = "Flags extras do agente (env FOSC_ARGS)."
  type        = string
  default     = "--continuous --interval 3600"
}

variable "max_hunts" {
  description = "Teto global de caçadas simultâneas (env SENTINELA_MAX_HUNTS)."
  type        = number
  default     = 5
}

variable "task_cpu" {
  description = "CPU da task Fargate (unidades)."
  type        = string
  default     = "1024"
}

variable "task_memory" {
  description = "Memória da task Fargate (MiB)."
  type        = string
  default     = "4096"
}

variable "desired_count" {
  description = "Réplicas do serviço ECS. 0 = nada roda até você subir (evita custo surpresa). O worker/consumidor da fila SQS roda aqui."
  type        = number
  default     = 0
}

# --- Bedrock (inference-profile ids por papel) ----------------------------------
variable "bedrock_sonnet" {
  type    = string
  default = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
}

variable "bedrock_opus" {
  type    = string
  default = "us.anthropic.claude-opus-4-1-20250805-v1:0"
}

variable "bedrock_haiku" {
  type    = string
  default = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}

# --- Segredo do Telegram (aprovação remota) -------------------------------------
# NÃO comitar valores reais. Passe via TF_VAR_* ou um .tfvars fora do git.
variable "telegram_token" {
  description = "Bot token do Telegram. Vazio cria o segredo com placeholder p/ você preencher depois."
  type        = string
  default     = ""
  sensitive   = true
}

variable "telegram_chat_id" {
  description = "Chat id do Telegram (operador)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "tags" {
  description = "Tags aplicadas a todos os recursos."
  type        = map(string)
  default = {
    Project = "bb-sentinela"
    Managed = "terraform"
  }
}
