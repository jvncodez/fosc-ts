# Segredo do Telegram (aprovação remota). Fora do repo e da imagem.
# O valor real NÃO fica no state em texto se você passar via TF_VAR_* só na hora
# do apply; ainda assim o state é sensível — use backend S3 cifrado + lock.

resource "aws_secretsmanager_secret" "telegram" {
  name        = "${local.name}/telegram"
  description = "BB-Sentinela — bot token + chat id p/ aprovação humana remota."
}

locals {
  telegram_has_values = var.telegram_token != "" && var.telegram_chat_id != ""
}

resource "aws_secretsmanager_secret_version" "telegram" {
  secret_id = aws_secretsmanager_secret.telegram.id
  secret_string = jsonencode({
    token   = var.telegram_token != "" ? var.telegram_token : "PREENCHA_NO_CONSOLE"
    chat_id = var.telegram_chat_id != "" ? var.telegram_chat_id : "PREENCHA_NO_CONSOLE"
  })

  # Se você preferir preencher o segredo pelo console depois, o Terraform não
  # sobrescreve mudanças manuais do valor.
  lifecycle {
    ignore_changes = [secret_string]
  }
}
