# Design — Autorização nativa AWS

Detalhe completo em [`deploy/AWS-AUTORIZACAO.md`](../../../deploy/AWS-AUTORIZACAO.md)
(seções 1–8: arquitetura, schema DynamoDB, contrato da API, policies, boundary,
pilares de trust). Resumo executável para o Kiro:

## Visão geral — 5 camadas
```
 Humano(SSO) ─► Cognito ─JWT─► API Gateway ─► Lambda approval-handler
                                                   │ (confere grupo)
                                                   ▼
 ECS task (authz.require) ◄─poll─ DynamoDB bb-sentinela-approvals ─stream─► audit hash-chain
        │ PARA no gate                 ▲ só Lambda grava decisão
        ▼                              │ task role só grava PENDING (separação de deveres)
   alvo (via proxy + SG de egress fechado)         Trilha: CloudTrail + audit.jsonl + DDB stream
```

## Componentes a construir
| Componente | Onde | Função |
|------------|------|--------|
| Permission boundary + SCP + OIDC provider | `deploy/terraform/authz/` | teto imutável + CI sem chave |
| Cognito (federado ao Identity Center) | `deploy/terraform/approval/` | identidade do operador (RA1) |
| DynamoDB + KMS + stream | `deploy/terraform/approval/` | ledger à prova de adulteração (RA4) |
| Lambda `approval-handler` | `lambda/approval_handler/` | valida grupo, grava decisão (RA2/RA3) |
| Lambda `audit-chain` | `lambda/audit_chain/` | stream → `audit.jsonl` hash-chain (RA4) |
| API Gateway (HTTP) + JWT authorizer | `deploy/terraform/approval/` | superfície de decisão (RA2) |
| mini-UI (S3+CloudFront, Cognito PKCE) | `web/approval/` ou reuso do `web/` | aprovar do navegador/celular |
| Backend DynamoDB no `fosc/authz.py` | código do agente | `SENTINELA_APPROVALS=dynamodb` (RA6) |

## Decisões de design
- **Separação de deveres via IAM condition** (RA3): a condição
  `dynamodb:Attributes` na policy da task role é o que impede o agente de gravar
  `APPROVED`. É a trava central; teste 1 do aceite valida.
- **Mesma interface `ApprovalStore`**: o backend DynamoDB implementa
  `require/on_pending/decide/pending()` sem mudar o `engine.py`. Seleção por env.
  Mantém o comportamento local (bloqueio do teste ativo) intacto.
- **Três trilhas independentes** (RA4): `audit.jsonl` (agente), DDB Stream (ledger),
  CloudTrail (API/IAM). Divergência entre elas = alarme.
- **Boundary em toda role** (RA5): aplicada no Terraform como `permissions_boundary`
  de cada `aws_iam_role` do projeto.
- **OIDC, não chave** (RA7): trust policy restrita a repo/branch.
- **Telegram** permanece como canal de alerta opcional (não é mais a fonte da
  decisão); desligável por env.

## Testabilidade
Os 8 critérios de aceite (seção 10 do blueprint) viram testes: `UpdateItem`
negado p/ a task role, 403 fora do grupo, cadeia quebrada detectada, boundary
prevalece, egress fechado, HALT preserva evidência.
