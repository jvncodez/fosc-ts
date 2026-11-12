# BB-Sentinela — provider, identidade e valores derivados.

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = var.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = var.aws_region
  name       = var.name_prefix

  # ARNs dos modelos Bedrock aprovados (foundation + inference-profile) p/ o IAM mínimo.
  bedrock_model_ids = [var.bedrock_sonnet, var.bedrock_opus, var.bedrock_haiku]

  # inference-profile id "us.anthropic.xxx" -> foundation-model "anthropic.xxx"
  bedrock_foundation_arns = [
    for id in local.bedrock_model_ids :
    "arn:aws:bedrock:${local.region}::foundation-model/${replace(id, "us.", "")}"
  ]
  bedrock_profile_arns = [
    for id in local.bedrock_model_ids :
    "arn:aws:bedrock:${local.region}:${local.account_id}:inference-profile/${id}"
  ]
}
