# Deploy — BB-Sentinela no AWS (Fargate + Bedrock)

Execução **headless** do agente na AWS, com **estado persistente**, **segredos fora
do repo** e **aprovação humana remota**. O modelo é o Amazon Bedrock; a governança
(escopo estrito na rede, human-in-the-loop, trilha de auditoria) vai junto.

## Instalação rápida via Docker (nada na máquina além da imagem)

```bash
bash install.sh      # builda a imagem com o arsenal completo + cria o volume de estado
```

Ao final, o script imprime os comandos `docker run` para rodar (dev/Anthropic ou
produção/Bedrock) e para operar/auditar (`fosc --audit/--approve/--halt` via volume).
O resto deste documento é o deploy em produção no AWS.

## Arquitetura

```
  Operador (celular)                         AWS
  ┌───────────────┐   aprova/nega/halt   ┌──────────────────────────────┐
  │   Telegram     │◄────────────────────►│  ECS Fargate task             │
  └───────────────┘   (long-poll)        │   BB-Sentinela (container)     │
                                          │   ├─ claude CLI → Bedrock      │
  Secrets Manager ──TELEGRAM_TOKEN/CHAT──►│   ├─ proxy de escopo (G0)      │
  Bedrock (taskRole) ──InvokeModel───────►│   └─ SENTINELA_HOME → EFS      │
  EFS (volume) ──estado/trilha/pocs──────►│                                │
  CloudWatch Logs ◄──────────────────────┤                                │
                                          └──────────────────────────────┘
```

Pontos-chave:
- **Segredos nunca na imagem:** `TELEGRAM_TOKEN`/`TELEGRAM_CHAT_ID` vêm do Secrets
  Manager como env (`notify.telegram_cfg` lê do env). O Bedrock é autenticado pela
  **task role** (sem chaves).
- **Estado persistente:** `SENTINELA_HOME=/data` montado em **EFS** — runs, trilha
  de auditoria (`audit.jsonl`), conhecimento e PoCs sobrevivem ao fim da task.
- **Escopo garantido pela rede, não por IAM:** a task role não tem permissão
  nenhuma sobre o alvo; quem impede a fuga é o proxy (`SENTINELA_SCOPE_PROXY=1`).
- **Headless + human-in-the-loop:** `SENTINELA_AUTHZ=ask` (o entrypoint recusa
  `yolo`). O gate de teste ativo para e espera a aprovação — que chega pelo Telegram.

## Passo a passo

### 1. Build e push da imagem (ECR)
```bash
aws ecr create-repository --repository-name bb-sentinela
aws ecr get-login-password --region <AWS_REGION> \
  | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com
docker build -f deploy/Dockerfile -t bb-sentinela .
docker tag bb-sentinela:latest <ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com/bb-sentinela:latest
docker push <ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com/bb-sentinela:latest
```

### 2. Bedrock
Habilite os modelos Claude no console do Bedrock (Model access) na sua região e
confira os **inference-profile ids** — ajuste `BEDROCK_SONNET/_OPUS/_HAIKU` na task
definition e os ARNs em `iam-task-role.json` se forem diferentes.

### 3. Estado persistente (EFS)
```bash
aws efs create-file-system --tags Key=Name,Value=bb-sentinela-state
# crie mount targets nas subnets da task e um Access Point (uid/gid 1000, path /sentinela)
# coloque o <EFS_FILE_SYSTEM_ID> e <EFS_ACCESS_POINT_ID> na task definition
```

### 4. Segredos (fora do repo)
```bash
aws secretsmanager create-secret --name bb-sentinela/telegram \
  --secret-string '{"token":"<BOT_TOKEN>","chat_id":"<CHAT_ID>"}'
# o ARN vai nos `secrets` da task definition (campos token:: e chat_id::)
```

### 5. IAM
Crie a **task role** com `deploy/iam-task-role.json` (menor privilégio: Bedrock +
segredo + EFS + logs) e a **execution role** padrão do ECS (puxar imagem do ECR,
ler o segredo, escrever logs).

### 6. Registrar e rodar
```bash
aws ecs register-task-definition --cli-input-json file://deploy/ecs-task-definition.json
aws ecs run-task --cluster <CLUSTER> --launch-type FARGATE \
  --task-definition bb-sentinela \
  --network-configuration 'awsvpcConfiguration={subnets=[<SUBNET>],securityGroups=[<SG>],assignPublicIp=ENABLED}'
```

### 7. Operar (remoto)
- A campanha inicia, faz recon, e **para no gate de teste ativo** → chega no
  Telegram uma mensagem com **✅ Aprovar / ❌ Negar**. Só depois do toque o teste
  ativo roda. `/status` e `/halt` também funcionam pelo chat.
- A qualquer momento, parada de emergência: `/halt` no Telegram **ou**
  `fosc --halt -a <TARGET>` (encerra tarefas em voo, preserva evidências).

### 8. Evidências e auditoria
Tudo fica no EFS sob `SENTINELA_HOME/runs/<alvo>/`:
`audit.jsonl` (trilha encadeada por hash), `executive_summary.md`, `pocs/<id>/`.
Verifique a integridade da cadeia a qualquer momento:
```bash
fosc --audit -a <TARGET>     # imprime a trilha e diz ÍNTEGRA ✓ / VIOLADA ✗
```

## Arsenal de pentest

A imagem traz o arsenal completo no PATH (o agente descobre o que está instalado
via `toolrunner.arsenal_note()` e usa via Bash):

| Categoria | Ferramentas |
|-----------|-------------|
| Subdomínios/DNS | subfinder, assetfinder, dnsx |
| Descoberta HTTP | httpx, katana, gau, waybackurls, hakrawler |
| Portas/serviços | **nmap**, masscan |
| Conteúdo/fuzzing | ffuf, feroxbuster, gobuster, dirsearch |
| Scan de vulnerabilidade | nuclei (+templates), nikto |
| Exploração web | sqlmap, dalfox, arjun |
| Fingerprint/WAF | whatweb, wafw00f |
| Wordlists | SecLists/Discovery em `/usr/share/seclists` |

Para instalar o mesmo arsenal na sua máquina local (dev): `bash scripts/install-tools.sh`.

> ⚠️ **Escopo e scanners de porta:** `nmap`/`masscan` fazem TCP cru e **não passam
> pelo proxy de escopo** (que é HTTP). Em produção, restrinja a saída do container
> no **security group / NACL** aos IPs do alvo. Ver `.kiro/steering/deploy.md`.

## Variáveis de ambiente (contrato do container)

| Env | Papel |
|-----|-------|
| `AWS_REGION` | obrigatório (Bedrock) |
| `TARGET` | URL do escopo autorizado (obrigatório) |
| `SENTINELA_HOME` | estado persistente (volume EFS) — default `/data` |
| `SENTINELA_PROVIDER` | `bedrock` |
| `SENTINELA_AUTHZ` | `ask` (headless recusa `yolo`) |
| `SENTINELA_SCOPE_PROXY` | `1` (enforcement de escopo na rede) |
| `BEDROCK_SONNET/_OPUS/_HAIKU` | inference-profile ids por papel |
| `TELEGRAM_TOKEN` / `TELEGRAM_CHAT_ID` | Secrets Manager (aprovação remota) |
| `FOSC_ARGS` | flags extras (`--continuous --interval 3600 --max-items 20`) |
