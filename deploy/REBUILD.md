# Rebuild & deploy do painel/worker na AWS (sem Kiro)

Passo-a-passo pra subir uma nova versão do código pra produção **sem depender do
agente do Kiro** — só um terminal com acesso AWS (o terminal do workshop / VS Code
onde o `docker` já funcionou, onde este repo está clonado).

As mudanças de **frontend** (`web/…`) o ECS serve estático e recarregam sozinhas.
As mudanças de **Python** (`fosc/…`) estão na imagem Docker → precisam de rebuild +
push + redeploy. Este runbook é pra esse caso.

## Dados fixos do ambiente

| | |
|---|---|
| Conta AWS | `521734861013` |
| Região | `us-east-1` |
| ECR repo | `521734861013.dkr.ecr.us-east-1.amazonaws.com/bb-sentinela` |
| Cluster ECS | `bb-sentinela` |
| Serviço do painel | `bb-sentinela-panel` |
| Serviço do worker | `bb-sentinela` (fica em `desired_count=0` até rodar caçada) |
| Dockerfile | `deploy/Dockerfile` |

## Passo-a-passo (copiar e colar)

```bash
# --- variáveis ---
export ACCOUNT=521734861013
export REGION=us-east-1
export REPO=$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/bb-sentinela
export CLUSTER=bb-sentinela
export PANEL=bb-sentinela-panel

# 0) pega o código novo (na pasta do repo)
git pull

# 1) login no ECR
aws ecr get-login-password --region $REGION \
  | sudo docker login --username AWS --password-stdin $ACCOUNT.dkr.ecr.$REGION.amazonaws.com

# 2) build da imagem (contexto = raiz do repo, Dockerfile em deploy/)
sudo docker build -t $REPO:latest -f deploy/Dockerfile .

# 3) (opcional, recomendado) confirma que a imagem importa sem erro
sudo docker run --rm --entrypoint python3 $REPO:latest -c "import fosc.webview, fosc.wsview, fosc.jobqueue, boto3; print('imports ok')"

# 4) push pro ECR
sudo docker push $REPO:latest

# 5) redeploy — a tag é :latest, o ECS não troca sozinho, tem que forçar
#    PAINEL (web):
aws ecs update-service --cluster $CLUSTER --service $PANEL \
  --force-new-deployment --region $REGION \
  --query 'service.{status:deployments[0].status,desired:desiredCount}' --output json
#    WORKER (quem caça) — só surte efeito quando desired_count>=1, mas não custa
aws ecs update-service --cluster $CLUSTER --service $CLUSTER \
  --force-new-deployment --region $REGION >/dev/null

# 6) espera estabilizar
aws ecs wait services-stable --cluster $CLUSTER --services $PANEL --region $REGION && echo "painel estável"

# 7) valida (a URL pública é a do API Gateway — ajuste se necessário)
export PANEL_URL=https://vl66igtq4j.execute-api.us-east-1.amazonaws.com
curl -sS -o /dev/null -w 'root=%{http_code}\n'        $PANEL_URL/ --max-time 15
curl -sS -o /dev/null -w 'auth-config=%{http_code}\n' $PANEL_URL/auth/config --max-time 15
# ambos devem dar 200

# 8) (opcional) olha os logs recentes do painel
aws logs tail /ecs/$PANEL --region $REGION --since 5m --format short | tail -30
```

## Subir o worker pra rodar uma caçada

O worker fica parado (`desired_count=0`) pra não gerar custo. Ele usa a MESMA
imagem `:latest`, então sobe já com o código novo. Pra ligar:

```bash
aws ecs update-service --cluster $CLUSTER --service $CLUSTER \
  --desired-count 1 --region $REGION
# logs do worker:
aws logs tail /ecs/$CLUSTER --region $REGION --since 5m --format short | tail -40
```

Pra parar de novo: `--desired-count 0`.

> ⚠️ **Sempre pelo `aws ecs update-service`, nunca pelo Terraform.** O serviço do
> worker tem `lifecycle { ignore_changes = [desired_count] }` — o Terraform
> **ignora** esse campo de propósito, então mexer no `terraform.tfvars` não
> sobe/para o worker.

## Mudanças de INFRA (Terraform) — fluxo separado

Pra qualquer alteração em `deploy/terraform/*.tf` ou no `terraform.tfvars`
(ex.: aplicar as faixas de CIDR da Cloudflare). **Não precisa rebuild de imagem.**

```bash
cd deploy/terraform

terraform init       # só se mudou provider/backend
terraform validate   # sintaxe

# gera e SALVA o plano
terraform plan -out=meuplano.tfplan
# >>> LEIA o diff (regra de ouro: nunca aplicar sem revisar) <<<

# aplica EXATAMENTE o que foi revisado (usa o plano salvo, não gera outro)
terraform apply meuplano.tfplan

terraform output     # URLs, ARNs, nomes de recursos
```

- `terraform.tfvars` **não é commitado** (segredo de rede/conta). Edite direto;
  não precisa regenerar do `.example` toda vez. O `.example` no repo serve só de
  referência (já tem CIDR da Cloudflare + modelos Bedrock 5.x corretos).
- Mudança de `.tf`/`.tfvars` só vale depois do `apply` — sem build de imagem.

> **Antes de rodar caçada real** garanta que `allowed_target_cidrs` já foi aplicado
> (faixas da Cloudflare, não o placeholder `127.0.0.1/32`) via `terraform apply`.
> O alvo é por URL/host (`target_url`), o escopo real é o `scope.py` +
> `SENTINELA_SCOPE_PROXY=1`.

## Rollback rápido

Se a versão nova quebrar, volte pra uma imagem anterior por digest:

```bash
# lista as imagens no ECR (mais recentes primeiro)
aws ecr describe-images --repository-name bb-sentinela --region $REGION \
  --query 'reverse(sort_by(imageDetails,&imagePushedAt))[].{pushed:imagePushedAt,digest:imageDigest,tags:imageTags}' \
  --output table
# re-taggeia o digest bom como latest e dá push, depois force-new-deployment do painel
```

## Notas

- `sudo` no `docker` segue o que já funcionou no ambiente do workshop; se o seu
  usuário estiver no grupo `docker`, pode tirar o `sudo`.
- O redeploy re-puxa `:latest` porque a task definition aponta pra essa tag —
  não precisa criar revisão nova da task definition pra uma troca só de código.
- AWS CloudShell normalmente **não** faz `docker build`; use o terminal do
  workshop/VS Code onde o build do Kiro rodou.
