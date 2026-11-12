# Repositório ECR da imagem do agente (arsenal completo).
resource "aws_ecr_repository" "sentinela" {
  name                 = local.name
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

# Mantém só as 10 imagens mais recentes.
resource "aws_ecr_lifecycle_policy" "sentinela" {
  repository = aws_ecr_repository.sentinela.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Manter as 10 imagens mais recentes"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}
