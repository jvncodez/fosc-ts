# BB-Sentinela na AWS — Implementação de Autorização Confiável

Blueprint de deploy com a **autorização como espinha dorsal**. Decisões fixadas:
aprovação humana **nativa AWS** (Cognito + API Gateway + Lambda + mini-UI, ledger
em DynamoDB), identidade humana via **IAM Identity Center (SSO)**, CI via **OIDC**.
Alinha com `.kiro/steering/governance.md`, `deploy/terraform/` e o **Authorization
Engine** do desafio do Banco do Brasil.

Princípio-mãe: **nada confia em nada por padrão**. Cada elo prova quem é, só pode o
mínimo, e deixa rastro imutável. O agente é poderoso mas **não se autoriza**.

---

## 1. As 5 camadas de autorização

```
  Humano (SSO)                                   AWS
  ┌────────────────┐                   ┌─────────────────────────────────────────┐
  │ IAM Identity   │  OIDC/SAML        │  (1) IDENTIDADE                           │
  │ Center (SSO)   │──federação───────►│   Cognito User Pool (operadores)          │
  └────────────────┘                   │   grupo: sentinela-approvers              │
         │ JWT curto                   │                                           │
         ▼                             │  (2) DECISÃO (API)                        │
  ┌────────────────┐  POST /approve    │   API Gateway (HTTP) + JWT authorizer     │
  │ mini-UI aprov. │──────────────────►│   └─ Lambda approval-handler              │
  │ (S3+CloudFront)│                   │        valida grupo → grava decisão       │
  └────────────────┘                   │        em DynamoDB (quem/quando/motivo)   │
                                        │                                           │
  ┌────────────────┐                   │  (3) LEDGER                               │
  │ ECS Fargate    │  poll decisão     │   DynamoDB bb-sentinela-approvals         │
  │ bb-sentinela   │◄──────────────────┤   (stream → auditoria hash-chain)         │
  │  authz.require()│                   │                                           │
  │  PARA no gate  │                   │  (4) EXECUÇÃO sob IAM mínimo              │
  └────────────────┘                   │   task role: Bedrock + fila + EFS + DDB   │
         │                             │   permission boundary trava o teto        │
         ▼                             │                                           │
  alvo autorizado                      │  (5) REDE: egress fechado (VPC endpoints   │
  (só via proxy + SG)                  │   + SG só p/ CIDRs do alvo) = proxy G0     │
                                        └─────────────────────────────────────────┘
       Trilha: CloudTrail (API/IAM) + audit.jsonl hash-chain (agente) + DDB stream
```

| # | Camada | Pergunta que responde | Serviço AWS |
|---|--------|-----------------------|-------------|
| 1 | Identidade | *Quem é você?* | IAM Identity Center → Cognito |
| 2 | Decisão | *Você autoriza esta ação?* | API Gateway + Lambda |
| 3 | Ledger | *O que foi decidido, por quem?* | DynamoDB + Streams |
| 4 | Execução | *O que o agente pode tocar?* | IAM role + permission boundary |
| 5 | Rede/Escopo | *Até onde o tráfego vai?* | VPC endpoints + SG + proxy |

Nenhuma camada sozinha basta. **Separação de deveres** é a regra central: a *task
role* do agente pode **ler** o ledger e **escrever um pedido** (`PENDING`), mas **não
pode escrever uma decisão** (`APPROVED/DENIED`). Só a Lambda — invocada por um humano
autenticado no grupo `sentinela-approvers` — grava a decisão. Assim, mesmo um agente
comprometido ou vítima de prompt-injection **não consegue se autoliberar**.

---

## 2. Camada 1 — Identidade (IAM Identity Center → Cognito)

**Humanos nunca recebem chave de longa duração.** Operadores entram pelo seu SSO
corporativo; o Cognito apenas federa essa identidade para a API de aprovação.

1. **IAM Identity Center** como IdP (você já usa). Crie:
   - Permission set `SentinelaOperator` (acesso de leitura ao console + assumir
     nada na conta do agente além do necessário p/ observar).
   - Permission set `SentinelaAdmin` (aplica Terraform; ver OIDC/CI abaixo).
   - Grupo de diretório `sentinela-approvers` → só quem pode aprovar gates.
2. **Cognito User Pool** federado ao Identity Center via **SAML 2.0** (ou OIDC).
   - App client sem segredo (mini-UI é SPA: PKCE).
   - Mapeie o grupo SSO `sentinela-approvers` → claim `cognito:groups`.
   - Tokens curtos (access 15 min, refresh 1 h). MFA herdado do SSO.
3. Resultado: aprovar exige **login corporativo + pertencer ao grupo**. Revogar um
   aprovador = tirar do grupo no Identity Center. Zero credencial parada.

> Por que não IAM user/chave para o operador? Porque chave vaza e não expira. SSO
> dá credencial efêmera, MFA e trilha central — requisito de confiabilidade.

---

## 3. Camada 2 — Decisão (API Gateway + Lambda)

**API Gateway HTTP API** com **JWT authorizer** apontando pro Cognito. Rotas:

| Método | Rota | Quem | Ação |
|--------|------|------|------|
| GET | `/approvals` | grupo approvers | lista gates `PENDING` |
| POST | `/approvals/{id}/approve` | grupo approvers | grava `APPROVED` |
| POST | `/approvals/{id}/deny` | grupo approvers | grava `DENIED` |
| POST | `/halt` | grupo approvers | dispara parada de emergência |

**Lambda `approval-handler`** (least privilege: só `dynamodb:UpdateItem`
condicionado + `PutEvents`):
1. Valida o JWT (authorizer já fez) e **confere `cognito:groups` contém
   `sentinela-approvers`** — autorização no código, não só na rede.
2. `UpdateItem` **condicional**: `attribute_exists(id) AND status = PENDING`
   (idempotência — aprovar duas vezes não reabre; corrida resolvida pelo DDB).
3. Grava `decided_by` (sub do Cognito = identidade real), `decided_at`, `reason`.
4. Emite evento no **EventBridge** → encadeia na trilha de auditoria.

Toda chamada à API vira registro no **CloudTrail** (quem, de onde, quando).

---

## 4. Camada 3 — Ledger (DynamoDB `bb-sentinela-approvals`)

Fonte da verdade da autorização, substituindo o `approvals.jsonl` local por um
store serverless, consistente e com stream.

```
PK  run_id         (ex.: https___1.migbot.com.br)
SK  approval_id    (ex.: 82e08f46f2)
    kind           active-hunt | privesc | ...
    scope          1.migbot.com.br [estrito]
    summary        "iniciar teste ATIVO de 84 endpoint(s)"
    status         PENDING | APPROVED | DENIED
    requested_by   task role ARN (o agente)
    decided_by     Cognito sub (o humano) | null
    decided_at     epoch | null
    reason         texto
    hash_prev      encadeamento (tamper-evidence)
```

- **Agente** (task role): `PutItem` só com `status=PENDING`; `GetItem/Query` p/ polling.
  Negado explicitamente escrever `APPROVED/DENIED` (condition + policy) → **não se
  aprova**.
- **Lambda** (approver): `UpdateItem` condicional p/ a decisão.
- **DynamoDB Stream** → Lambda `audit-chain` que anexa o registro à trilha
  hash-chained (`audit.jsonl` no EFS) — a mesma cadeia SHA-256 que o `fosc/audit.py`
  já usa, agora alimentada também pelas decisões da API.
- Criptografia em repouso com **KMS CMK** próprio; point-in-time recovery ligado.

### Mudança no agente (`fosc/authz.py`)
Hoje o `ApprovalStore` grava/lê `approvals.jsonl`. Adicionar um **backend DynamoDB**
atrás da mesma interface (`require()`, `on_pending`, `decide()`), selecionado por env
`SENTINELA_APPROVALS=dynamodb` + `SENTINELA_APPROVALS_TABLE`. `require()` passa a dar
`PutItem(PENDING)` e **poll** (`GetItem`, backoff) até `status != PENDING`. O gate
continua **bloqueando o teste ativo** exatamente como no local — só a origem da
decisão muda para a API autenticada. Mantém o Telegram desligado (ou como alerta).

---

## 5. Camada 4 — Execução sob IAM mínimo + permission boundary

A `task role` (já no `deploy/terraform/iam.tf`) ganha só o acesso ao ledger:

```
+ Sid ApprovalsLedger
  Allow dynamodb:PutItem, GetItem, Query   on table/bb-sentinela-approvals
  Condition (PutItem): dynamodb:Attributes status = PENDING   # não grava decisão
```

**Permission boundary** `bb-sentinela-boundary` anexada a TODAS as roles do projeto
(task, execution, lambdas): um teto que nenhuma policy pode furar — mesmo que alguém
amplie uma role por engano, a boundary nega tudo fora de {Bedrock aprovado, SQS,
EFS, DDB approvals, Secrets do projeto, Logs}. **Nunca** `iam:*`, `sts:AssumeRole`
amplo, nem permissão sobre o alvo. É a trava de confiabilidade contra erro humano.

Reforços de conta:
- **SCP** (se org): nega `iam:CreateUser`, criação de access key, e uso fora das
  regiões aprovadas, na OU do projeto.
- O agente **autentica no Bedrock pela role** (sem chave). Modelo é configuração
  (`BEDROCK_*`), nunca código.

---

## 6. Camada 5 — Rede/Escopo (já no Terraform)

`deploy/terraform/network.tf`: egress da task fechado — só os **CIDRs do alvo
autorizado** (80/443) e AWS via **VPC endpoints**, sem internet geral. Contém
nmap/masscan (TCP cru que fura o proxy HTTP). É a autorização *de alcance*: a rede
só deixa sair para onde o escopo permite. Ver `.kiro/steering/infra.md`.

---

## 7. Mini-UI de aprovação

SPA estática (**S3 + CloudFront**, OAC, HTTPS only), login Cognito (PKCE). Pode
reusar a view de aprovação do painel `web/` já existente, apontando o `fetch` para
a API Gateway com o `Authorization: Bearer <id_token>`. Mostra os gates `PENDING`
(GET `/approvals`), com botões Aprovar/Negar e campo de motivo. Botão **HALT**
separado (confirmação dupla). Mobile-friendly: aprovar do celular, como o Telegram,
mas com identidade corporativa.

---

## 8. Confiabilidade / trust (o "de forma confiável")

| Pilar | Como |
|-------|------|
| Sem credencial parada | SSO (humano) + role (agente) + OIDC (CI). Zero chave longa. |
| Least privilege + boundary | Teto imutável por role; SCP na OU. |
| Separação de deveres | Agente pede, humano decide; agente não grava decisão. |
| Tamper-evidence | audit.jsonl hash-chain + DDB Stream + CloudTrail (3 trilhas independentes). |
| Criptografia | KMS CMK em DDB, EFS, Secrets, SQS; TLS in-transit; S3/UI só HTTPS. |
| Detecção | GuardDuty + EventBridge → alerta em `DENIED`/`HALT`/erro de scope. |
| Resiliência | IaC idempotente, state S3 cifrado + lock DynamoDB, multi-AZ no EFS/SQS. |
| Reprodutibilidade | Tudo em Terraform; nada criado à mão (steering do Kiro). |
| Rotação | Secrets Manager com rotação; tokens Cognito curtos. |

---

## 9. Sequência de deploy (runbook)

> Driver: **Kiro Code aplicando o Terraform** (ver `.kiro/steering/infra.md`). CI
> opcional via GitHub Actions + OIDC (sem chave na pipeline).

1. **Pré-flight**
   - Bedrock: Model access aos Claude na região; anote os inference-profile ids.
   - Identity Center: permission sets + grupo `sentinela-approvers`.
   - VPC/subnets existentes; `allowed_target_cidrs` = IP do alvo.
2. **Base de identidade/boundary** (novo módulo `deploy/terraform/authz/`)
   - permission boundary, (SCP se org), OIDC provider p/ GitHub Actions.
3. **Núcleo** (`deploy/terraform/` que já existe)
   - ECR, ECS, EFS, SQS, Secrets, IAM (com boundary anexada), rede/endpoints, logs.
4. **Plano de autorização** (novo `deploy/terraform/approval/`)
   - Cognito (federado ao Identity Center), DynamoDB + KMS + stream, Lambdas
     (`approval-handler`, `audit-chain`), API Gateway + JWT authorizer, S3+CloudFront
     da mini-UI.
5. **Imagem**: build + push ao ECR (`deploy/Dockerfile`); o agente sobe com
   `SENTINELA_APPROVALS=dynamodb`.
6. **Smoke test de autorização** (seção 10) antes de qualquer teste ativo real.
7. **Operar**: subir o service (worker da fila); aprovar gates pela mini-UI;
   `fosc --audit` + CloudTrail p/ conferir a cadeia.

### CI via OIDC (sem chave)
GitHub Actions assume uma role via **OIDC** (trust: `token.actions.githubusercontent.com`,
condição no `sub` = repo/branch), com a boundary do projeto. `terraform plan` em PR,
`apply` só no `main` com aprovação de ambiente. Nenhuma AWS key no repo/CI.

---

## 10. Critérios de aceite (prova de que a autorização é confiável)

1. **Negação de auto-aprovação:** com as credenciais da task role, um `UpdateItem`
   tentando `status=APPROVED` é **negado por IAM** (teste explícito). ✅
2. **Gate bloqueia:** caçada nova fica `PENDING`; o teste ativo **não roda** até um
   humano do grupo aprovar pela UI. ✅
3. **Identidade real:** o registro `APPROVED` carrega o `sub` Cognito do operador e
   bate com o CloudTrail. ✅
4. **Fora do grupo = 403:** usuário autenticado mas sem `sentinela-approvers` recebe
   403 na API. ✅
5. **Tamper-evidence:** alterar um registro do ledger quebra a cadeia hash
   (`fosc --audit` acusa VIOLADA ✗). ✅
6. **Boundary:** anexar uma policy ampla (`iam:*`) a qualquer role do projeto não
   tem efeito — a boundary nega. ✅
7. **Escopo de rede:** a task não alcança nada fora de `allowed_target_cidrs` + AWS
   endpoints (teste de egress). ✅
8. **Halt:** `POST /halt` (ou `fosc --halt`) encerra o teste ativo e preserva as
   evidências no EFS. ✅

---

## 11. O que falta construir (próximos PRs)

- [ ] `deploy/terraform/authz/` — boundary, SCP, OIDC provider.
- [ ] `deploy/terraform/approval/` — Cognito, DynamoDB+KMS+stream, Lambdas, API GW, UI.
- [ ] `fosc/authz.py` — backend DynamoDB atrás da interface `ApprovalStore`
      (`SENTINELA_APPROVALS=dynamodb`), com polling e `PutItem(PENDING)`.
- [ ] `lambda/approval_handler/` e `lambda/audit_chain/` — código + testes.
- [ ] mini-UI: adaptar a view de aprovação do `web/` p/ Cognito + API Gateway.
- [ ] Testes de aceite 1–8 automatizados.

Este documento é o contrato. A implementação segue em módulos Terraform + código,
cada um com os testes de aceite acima.
