---
inclusion: fileMatch
fileMatchPattern: "deploy/terraform/**"
---

# Infra como código (Terraform) — fonte da verdade da AWS

O stack da AWS do bb-sentinela é definido em `deploy/terraform/`. Esse módulo é a
**única fonte da verdade** da infra. Vale junto com `.kiro/steering/deploy.md`
(convenções de deploy) e `.kiro/steering/governance.md` (regras invioláveis).

## Regra de ouro
- **Provisione aplicando o Terraform**, nunca criando recurso à mão no console ou
  com `aws ... create-*` avulso. Mudança de infra = editar `.tf` + `plan` + `apply`.
- Fluxo: `terraform init` → `terraform plan` (revisar o diff) → `terraform apply`.
  Nunca aplicar sem ler o plan. `terraform destroy` só com evidências do EFS já
  exportadas (o estado é persistente e tem valor probatório).
- Se faltar `terraform`/`aws` na máquina, instale antes; não recrie o stack por fora.

## O que o módulo provisiona (não duplicar por fora)
ECR · ECS Fargate (cluster + task definition + service worker da fila) · EFS
(FS + mount targets + access point uid/gid 1000) · SQS FIFO + DLQ · Secrets
Manager (Telegram) · IAM (task + execution role) · VPC endpoints + security groups
· CloudWatch Logs. Arquivos por recurso em `deploy/terraform/*.tf`; ver o README.

## Governança codificada — NÃO enfraquecer
Estas propriedades estão no `.tf` e são o motivo do módulo existir. Um `plan` que
as remova está errado:
- `SENTINELA_AUTHZ=ask` e `SENTINELA_SCOPE_PROXY=1` no container (headless com
  human-in-the-loop; escopo garantido na rede).
- **IAM de menor privilégio** (`iam.tf`): a task role só invoca os modelos Bedrock
  aprovados, lê o segredo do Telegram, monta o EFS (condicionado ao access point),
  usa a fila SQS e escreve logs. **Nenhuma permissão sobre o alvo.**
- **Egress fechado** (`network.tf`): o SG da task só libera 80/443 para os CIDRs do
  **alvo autorizado** (`allowed_target_cidrs`) e HTTPS para a AWS via **VPC
  endpoints** — sem internet geral. Essa é a contenção de rede para nmap/masscan
  (TCP cru que escapa do proxy HTTP). `create_vpc_endpoints=false` é fallback com
  NAT, menos estrito — só usar se não der para criar endpoints.
- **Segredos fora do repo e da imagem**: token/chat do Telegram entram por
  `TF_VAR_telegram_token`/`TF_VAR_telegram_chat_id` no `apply`, ou preenchidos no
  Secrets Manager depois. **Nunca** em `terraform.tfvars` comitado, em texto no
  `.tf`, nem no state não cifrado.
- **Estado no EFS** (`SENTINELA_HOME=/data`): runs, trilha de auditoria, conhecimento
  e PoCs. Nunca mover para a camada efêmera do container.

## O que preencher antes do apply
Em `terraform.tfvars` (copiado de `terraform.tfvars.example`):
- `vpc_id`, `private_subnet_ids` — VPC/subnets existentes (o módulo não cria VPC).
- `allowed_target_cidrs` — IP(s) do alvo autorizado (ex.: `["44.227.89.148/32"]`).
- `aws_region` e, se diferirem, os `bedrock_*` (inference-profile ids liberados).
- `desired_count` fica 0 (nada roda até subir o service) para não gerar custo surpresa.

## State e segurança
- Preferir **backend remoto S3 cifrado + lock DynamoDB** (bloco comentado em
  `versions.tf`) — o state guarda ARNs e referências sensíveis.
- `terraform.tfvars` e `*.tfstate` estão no `.gitignore` do módulo; mantê-los fora
  do git.

## Imagem
- Troca/adição de modelo é **configuração** (envs `BEDROCK_*`/`SENTINELA_PROVIDER` na
  task definition), nunca mudança de código — igual ao `deploy.md`.
- Após o `apply`, o build/push da imagem vai para o ECR criado (ver outputs
  `ecr_login_command` e `ecr_repository_url`), com o `deploy/Dockerfile`.
