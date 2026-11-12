---
inclusion: fileMatch
fileMatchPattern: "deploy/**"
---

# Deploy no AWS/Kiro — convenções

Execução headless na AWS (Fargate + Bedrock). Artefatos em `deploy/` (ver
`deploy/README.md`). Regras que não podem ser enfraquecidas:

## Segredos
- Nunca na imagem, no repo ou na task definition em texto. Vêm do **Secrets
  Manager** como env (`TELEGRAM_TOKEN`/`TELEGRAM_CHAT_ID`). O código lê do env em
  `notify.telegram_cfg`. O Bedrock é autenticado pela **task role**, sem chaves.

## Estado
- `SENTINELA_HOME=/data` montado em **EFS** (volume persistente): runs, trilha de
  auditoria, conhecimento e PoCs sobrevivem ao fim da task. Nunca gravar estado na
  camada efêmera do container.

## Governança em produção
- `SENTINELA_AUTHZ=ask` SEMPRE — o entrypoint **recusa `yolo`**. Headless não
  significa sem humano: o gate de teste ativo para e espera aprovação (Telegram ou
  `fosc --approve`).
- `SENTINELA_SCOPE_PROXY=1` SEMPRE — o escopo é garantido na **rede** (proxy), não
  por IAM. A task role não tem nenhuma permissão sobre o alvo.
- IAM de **menor privilégio** (`deploy/iam-task-role.json`): só Bedrock dos modelos
  aprovados, leitura do segredo, EFS e logs.

## Modelo
- Troca/adição de modelo é configuração (env `BEDROCK_*` + `SENTINELA_PROVIDER`),
  nunca mudança de código — ver `fosc/models.py` e `tech.md`. O failover cobre um
  modelo que falhe/recuse/fique lento.
