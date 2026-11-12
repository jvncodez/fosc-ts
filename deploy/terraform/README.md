# BB-Sentinela — Infra como código (Terraform)

Provisiona todo o stack da AWS do agente, reproduzível e auditável:

| Recurso | Arquivo | Papel |
|---------|---------|-------|
| ECR | `ecr.tf` | imagem do agente (arsenal completo) |
| ECS Fargate (cluster + task def + service) | `ecs.tf` | execução headless; service = worker da fila |
| EFS (FS + mount targets + access point) | `efs.tf` | estado persistente em `/data` |
| SQS FIFO (+ DLQ) | `sqs.tf` | fila de caçadas, "um alvo uma campanha" |
| Secrets Manager | `secrets.tf` | token/chat do Telegram (fora do repo) |
| IAM (task + execution role) | `iam.tf` | menor privilégio, nada sobre o alvo |
| VPC endpoints + security groups | `network.tf` | egress fechado: só o alvo + AWS, sem internet geral |
| CloudWatch Logs | `logs.tf` | logs do agente |

A governança do `.kiro/steering/deploy.md` está codificada aqui: `SENTINELA_AUTHZ=ask`,
`SENTINELA_SCOPE_PROXY=1`, IAM mínimo, segredos fora da imagem, estado no EFS e o
**egress em camadas** (fila determinística + proxy HTTP + firewall de rede p/ não-HTTP).

## Pré-requisitos
- Terraform ≥ 1.5 e credenciais AWS com permissão de criar os recursos acima.
- Uma **VPC** com **subnets** (passe os ids em `terraform.tfvars`). O módulo não cria VPC.
- **Bedrock**: habilite os modelos Claude (Model access) na região e confira os
  inference-profile ids (`bedrock_*`).

## Uso
```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars    # edite vpc_id, subnets, allowed_target_cidrs
terraform init
terraform plan
# segredo do Telegram só na hora do apply (não vai p/ o .tfvars):
TF_VAR_telegram_token='<BOT_TOKEN>' TF_VAR_telegram_chat_id='<CHAT_ID>' terraform apply
```

Depois do apply:
```bash
# 1. build + push da imagem p/ o ECR (o login e a URL saem nos outputs)
eval "$(terraform output -raw ecr_login_command)"
docker build -f ../Dockerfile -t "$(terraform output -raw ecr_repository_url):latest" ..
docker push "$(terraform output -raw ecr_repository_url):latest"

# 2a. subir o worker contínuo da fila
aws ecs update-service --cluster "$(terraform output -raw cluster_name)" \
  --service bb-sentinela --desired-count 1

# 2b. ou rodar uma campanha avulsa
eval "$(terraform output -raw run_task_command)"
```

## Provisionar via Kiro Code
Este módulo é a fonte da verdade da infra. Peça ao Kiro p/ aplicá-lo (não p/
recriar recursos à mão), passando o contexto de `.kiro/steering/deploy.md`:

> "Aplique o Terraform em `deploy/terraform/`. Preencha `vpc_id`,
> `private_subnet_ids` e `allowed_target_cidrs` (IP do alvo autorizado) no
> `terraform.tfvars`. Rode `terraform init && plan && apply`. Não enfraqueça a
> governança do steering: `SENTINELA_AUTHZ=ask`, `SENTINELA_SCOPE_PROXY=1`, IAM
> mínimo e egress fechado ao alvo. O token do Telegram vai por `TF_VAR_*`, nunca
> no tfvars."

## Custo e teardown
- `desired_count = 0` por padrão: nada roda (logo, sem custo de compute) até você
  subir o service ou rodar a task.
- Os VPC endpoints têm custo/hora. `create_vpc_endpoints = false` cai no fallback
  com NAT (menos estrito; só o egress HTTP fica aberto à internet p/ as APIs AWS).
- Derrubar tudo: `terraform destroy`. O EFS tem estado — exporte as evidências antes.
