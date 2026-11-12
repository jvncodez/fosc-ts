# Tarefas — Autorização nativa AWS

Legenda: [x] feito · [ ] a fazer. Cada tarefa referencia o requisito (RAn).
Contrato: [`deploy/AWS-AUTORIZACAO.md`](../../../deploy/AWS-AUTORIZACAO.md).
Construtor: **Kiro**. Não enfraquecer a governança dos steerings.

## Pré-requisitos (operador, fora do Terraform)
- [ ] 0.1 Bedrock Model access aos Claude na região; anotar inference-profile ids.
- [ ] 0.2 IAM Identity Center: permission sets `SentinelaOperator`/`SentinelaAdmin`
      + grupo de diretório `sentinela-approvers`. (RA1)
- [ ] 0.3 VPC/subnets e `allowed_target_cidrs` definidos no `terraform.tfvars`.

## Base de identidade e teto (`deploy/terraform/authz/`)
- [ ] 1. Permission boundary `bb-sentinela-boundary` (allowlist dos serviços do
      projeto; nega `iam:*`, assume-role amplo e acesso ao alvo). (RA5)
- [ ] 2. Anexar a boundary a TODAS as roles do projeto (task, execution, lambdas)
      via `permissions_boundary`. (RA5)
- [ ] 3. SCP na OU do projeto: negar criação de IAM user/access key e regiões fora
      das aprovadas (se houver AWS Organizations). (RA5)
- [ ] 4. OIDC provider p/ GitHub Actions + role de CI (trust por repo/branch). (RA7)

## Ledger e identidade (`deploy/terraform/approval/`)
- [ ] 5. KMS CMK do projeto (DDB, EFS, Secrets, SQS). (RA4)
- [ ] 6. DynamoDB `bb-sentinela-approvals` (PK `run_id`, SK `approval_id`, stream
      NEW_IMAGE, PITR, cifrado com a CMK). (RA4)
- [ ] 7. Cognito User Pool federado ao Identity Center (SAML/OIDC), app client PKCE,
      mapeamento do grupo → `cognito:groups`, tokens curtos. (RA1)

## Decisão (API + Lambdas)
- [ ] 8. Lambda `approval-handler` (`lambda/approval_handler/`): valida grupo
      `sentinela-approvers`, `UpdateItem` condicional (`status=PENDING`), grava
      `decided_by/decided_at/reason`, emite EventBridge. + testes. (RA2/RA3)
- [ ] 9. Lambda `audit-chain` (`lambda/audit_chain/`): DDB Stream → anexa à cadeia
      `audit.jsonl` (reusa `fosc/audit.py`). + testes. (RA4)
- [ ] 10. API Gateway HTTP + JWT authorizer Cognito; rotas `GET /approvals`,
      `POST /approvals/{id}/approve|deny`, `POST /halt`. (RA2/RA6)

## Agente AWS-native (código)
- [ ] 11. Backend DynamoDB no `fosc/authz.py` atrás da interface `ApprovalStore`
      (`SENTINELA_APPROVALS=dynamodb` + `_TABLE`): `PutItem(PENDING)` + polling;
      bloqueio do teste ativo inalterado. + testes offline (DDB fake). (RA3/RA6)
- [ ] 12. Task role `+ dynamodb:PutItem(cond status=PENDING)/GetItem/Query`;
      **negar** `UpdateItem/PutItem` com `APPROVED|DENIED`. (RA3)

## mini-UI
- [ ] 13. Adaptar a view de aprovação do `web/` p/ Cognito (PKCE) + API Gateway;
      publicar em S3+CloudFront (OAC, HTTPS only). Botão HALT com confirmação. (RA2/RA6)

## Aceite (automatizar)
- [ ] 14. Testes dos 8 critérios (seção 10 do blueprint): auto-aprovação negada,
      gate bloqueia, identidade real no registro, 403 fora do grupo, cadeia
      quebrada detectada, boundary prevalece, egress fechado, HALT preserva. (RA1–RA7)

## Deploy
- [ ] 15. Rodar via Kiro: `terraform init/plan/apply` em `authz/` → núcleo → `approval/`;
      build+push imagem com `SENTINELA_APPROVALS=dynamodb`; smoke test de autorização
      ANTES de qualquer teste ativo real.
