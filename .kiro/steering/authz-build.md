---
inclusion: fileMatch
fileMatchPattern: "{lambda/**,deploy/terraform/authz/**,deploy/terraform/approval/**,web/approval/**}"
---

# Construção da autorização nativa AWS — convenções (Kiro)

Você (Kiro) está construindo a autorização nativa AWS. A fonte é o spec
`.kiro/specs/aws-authorization/` (requirements/design/tasks) e o contrato
[`deploy/AWS-AUTORIZACAO.md`](../../deploy/AWS-AUTORIZACAO.md). Vale junto com
`governance.md`, `deploy.md` e `infra.md`.

## Não enfraquecer (invariantes)
- **Separação de deveres:** a task role do agente só grava `PENDING` e lê o ledger;
  é **negada por IAM** de gravar `APPROVED/DENIED`. Só a Lambda `approval-handler`,
  invocada por humano no grupo `sentinela-approvers`, decide. O agente **não se
  aprova** — nunca remova essa condição do DynamoDB.
- **Identidade real:** aprovação exige Cognito federado ao IAM Identity Center +
  pertencer ao grupo. Sem IAM user/chave de longa duração para operador.
- **Teto imutável:** `bb-sentinela-boundary` em TODA role do projeto (task,
  execution, lambdas). A boundary prevalece sobre qualquer policy ampla.
- **Três trilhas:** `audit.jsonl` (hash-chain), DynamoDB Stream e CloudTrail. O
  stream do ledger SEMPRE alimenta a cadeia (`fosc/audit.py`).
- **Gate bloqueia:** o teste ativo não começa sem decisão; `require()` continua
  bloqueando. HALT (`POST /halt`/`fosc --halt`) preserva evidências no EFS.
- **Sem chave:** CI por OIDC; segredos no Secrets Manager; nada no repo/imagem.

## Convenções
- IaC em Terraform aplicada por Kiro (`init/plan/apply`), nunca recurso à mão —
  igual `infra.md`. Módulos: `deploy/terraform/authz/` (boundary/SCP/OIDC) e
  `deploy/terraform/approval/` (Cognito/DDB/Lambda/API GW/UI).
- Lambdas em `lambda/<nome>/` com testes; reusar `fosc/audit.py` na `audit-chain`.
- Toda tarefa referencia um requisito (RAn) do spec; os 8 critérios de aceite da
  seção 10 do blueprint viram testes antes de qualquer teste ativo real.
- A interface `ApprovalStore` do `fosc/authz.py` não muda: o backend DynamoDB entra
  atrás dela, selecionado por `SENTINELA_APPROVALS=dynamodb`.
