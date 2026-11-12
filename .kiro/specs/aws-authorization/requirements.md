# Requisitos — Autorização nativa AWS (aprovação humana confiável)

## Introdução
Levar o **Authorization Engine** do agente para a AWS de forma **confiável**: a
aprovação humana passa a ser nativa (Cognito + API Gateway + Lambda + ledger em
DynamoDB), com identidade via **IAM Identity Center (SSO)** e CI via **OIDC**. O
contrato completo (arquitetura, schemas, policies, runbook, critérios de aceite)
está em [`deploy/AWS-AUTORIZACAO.md`](../../../deploy/AWS-AUTORIZACAO.md) — este spec
é a visão executável dele. Vale junto com `.kiro/steering/{governance,deploy,infra}.md`.

Princípio-mãe: **nada confia em nada por padrão**; o agente é poderoso mas **não se
autoriza**.

## Requisitos

### RA1 — Identidade humana sem credencial parada
**História:** Como operador, quero aprovar com minha identidade corporativa, para que
toda decisão tenha um dono real e rastreável.

Critérios (EARS):
1. O SISTEMA DEVE autenticar operadores via **Cognito federado ao IAM Identity
   Center** (SAML/OIDC), nunca por IAM user ou chave de longa duração.
2. QUANDO um operador autentica, O SISTEMA DEVE emitir tokens curtos (access ≤ 15min)
   com MFA herdada do SSO.
3. O SISTEMA DEVE expor o grupo `sentinela-approvers` no claim `cognito:groups`.
4. QUANDO um operador é removido do grupo no Identity Center, O SISTEMA DEVE deixar
   de aceitar suas aprovações sem necessidade de redeploy.

### RA2 — Decisão autorizada só por humano do grupo
**História:** Como responsável pela governança, quero que só aprovadores legítimos
decidam, para impedir liberação indevida.

Critérios (EARS):
1. O SISTEMA DEVE expor a decisão via **API Gateway com JWT authorizer** do Cognito.
2. A Lambda `approval-handler` DEVE **conferir no código** que `cognito:groups`
   contém `sentinela-approvers` ANTES de gravar, retornando 403 caso contrário.
3. QUANDO uma decisão é gravada, O SISTEMA DEVE registrar `decided_by` (sub do
   Cognito), `decided_at` e `reason`.
4. O SISTEMA DEVE ser idempotente: aprovar/negar um gate já decidido NÃO DEVE
   reabri-lo (UpdateItem condicional `status = PENDING`).

### RA3 — Separação de deveres (o agente não se aprova)
**História:** Como auditor, quero garantia técnica de que o próprio agente não pode
se liberar, mesmo se comprometido ou vítima de prompt-injection.

Critérios (EARS):
1. A **task role** do agente DEVE poder `PutItem` apenas com `status = PENDING` e
   ler o ledger (`GetItem/Query`).
2. A task role DEVE ser **negada por IAM** de gravar `status = APPROVED | DENIED`
   (condition nos atributos do DynamoDB).
3. Somente a Lambda `approval-handler` (invocada por humano autenticado) DEVE poder
   gravar a decisão.

### RA4 — Ledger como fonte da verdade, à prova de adulteração
**História:** Como auditor, quero um registro consistente e imutável de pedidos e
decisões.

Critérios (EARS):
1. O SISTEMA DEVE usar **DynamoDB `bb-sentinela-approvals`** (PK `run_id`, SK
   `approval_id`) como ledger, cifrado com **KMS CMK** e com PITR ligado.
2. O **DynamoDB Stream** DEVE alimentar a trilha hash-chain existente
   (`fosc/audit.py` / `audit.jsonl`), encadeando cada decisão.
3. QUANDO um registro do ledger for alterado fora do fluxo, `fosc --audit` DEVE
   acusar a cadeia como VIOLADA.

### RA5 — Teto imutável de privilégio
**História:** Como engenheiro de segurança, quero que erro humano não amplie o que o
agente pode fazer.

Critérios (EARS):
1. TODAS as roles do projeto (task, execution, lambdas) DEVEM ter a **permission
   boundary** `bb-sentinela-boundary` anexada.
2. A boundary DEVE negar tudo fora de {Bedrock aprovado, SQS, EFS, DDB approvals,
   Secrets do projeto, Logs}; nunca `iam:*` nem `sts:AssumeRole` amplo nem acesso ao
   alvo.
3. QUANDO uma policy ampla (`iam:*`) for anexada a uma role do projeto, O SISTEMA
   DEVE continuar negando (a boundary prevalece).

### RA6 — Gate bloqueia o teste ativo (continuidade do R3 local)
**História:** Como operador, quero que o teste ativo não comece sem meu aval.

Critérios (EARS):
1. QUANDO `SENTINELA_APPROVALS=dynamodb`, o `fosc/authz.py` DEVE usar o ledger
   DynamoDB atrás da mesma interface `ApprovalStore` (`require/on_pending/decide`).
2. `require()` DEVE gravar `PENDING` e **bloquear** o teste ativo até `status !=
   PENDING`, idêntico ao comportamento local.
3. O SISTEMA DEVE suportar **HALT** (`POST /halt` ou `fosc --halt`), encerrando o
   teste ativo e preservando as evidências no EFS.

### RA7 — CI e operação sem chave
**História:** Como mantenedor, quero aplicar a infra sem segredos no repo/pipeline.

Critérios (EARS):
1. O CI DEVE assumir role via **OIDC** (`token.actions.githubusercontent.com`,
   condição no `sub` = repo/branch), com a boundary do projeto.
2. `terraform apply` DEVE rodar só no `main` com aprovação de ambiente; `plan` em PR.
3. NENHUMA AWS access key DEVE existir no repo, na imagem ou no CI.

## Aceite
Os 8 critérios de aceite da seção 10 de `deploy/AWS-AUTORIZACAO.md` DEVEM passar
antes de qualquer teste ativo real em produção.
