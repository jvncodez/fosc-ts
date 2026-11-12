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

## Arsenal e escopo em camadas (IMPORTANTE)
- O container traz o arsenal completo (recon, enumeração, portas, fuzzing,
  exploração) — ver `deploy/Dockerfile` e `scripts/install-tools.sh`. O agente é
  informado do que está no PATH via `toolrunner.arsenal_note()` e usa via Bash.
- **O proxy de escopo só cobre HTTP/HTTPS (CONNECT).** `nmap`/`masscan`/`naabu`
  fazem TCP cru e **passam por fora dele**. Portanto:
  - O escopo para essas ferramentas é garantido pelo **note determinístico** no
    prompt (nível de agente), NÃO pela rede.
  - Em produção, feche a saída do container no **security group / NACL** para os
    IPs/portas do alvo autorizado — essa é a contenção de rede para não-HTTP.
  - Três camadas somadas: fila determinística (recon) + proxy HTTP (G0) + egress
    firewall (não-HTTP). Nenhuma sozinha é suficiente; juntas, fuga é inviável.
