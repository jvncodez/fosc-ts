# BB-Sentinela — requisitos de Terraform e provider.
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # Recomendado p/ equipe/hackathon: backend remoto com lock (descomente e ajuste).
  # backend "s3" {
  #   bucket         = "<SEU_BUCKET_TFSTATE>"
  #   key            = "bb-sentinela/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "<SUA_TABELA_LOCK>"
  #   encrypt        = true
  # }
}
