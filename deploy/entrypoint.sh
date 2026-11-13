#!/usr/bin/env bash
# BB-Sentinela — entrypoint do container (execução headless no AWS/Kiro).
#
# Segredos chegam como variáveis de ambiente injetadas pelo Secrets Manager
# (nunca embutidas na imagem). O estado vive em SENTINELA_HOME (volume EFS).
set -euo pipefail

: "${SENTINELA_HOME:=/data}"
mkdir -p "$SENTINELA_HOME"                      # volume EFS persistente

# AWS_REGION só é obrigatório no modo Bedrock (dev/Anthropic usa ANTHROPIC_API_KEY).
if [ "${SENTINELA_PROVIDER:-bedrock}" = "bedrock" ]; then
  : "${AWS_REGION:?AWS_REGION é obrigatório para o Bedrock}"
fi
: "${TARGET:?TARGET (URL do escopo autorizado) é obrigatório}"

echo "BB-Sentinela :: provider=${SENTINELA_PROVIDER:-bedrock} region=${AWS_REGION:-n/a} home=${SENTINELA_HOME}"
echo "BB-Sentinela :: scope-proxy=${SENTINELA_SCOPE_PROXY:-1} authz=${SENTINELA_AUTHZ:-ask}"
echo "BB-Sentinela :: alvo autorizado = ${TARGET}"

# Guard-rail de produção: autorização headless NÃO pode ser 'yolo'.
if [ "${SENTINELA_AUTHZ:-ask}" = "yolo" ]; then
  echo "ERRO: SENTINELA_AUTHZ=yolo é proibido em produção (sem human-in-the-loop)." >&2
  exit 2
fi

# Aprovação remota fica viva quando o Telegram é injetado (Secrets Manager).
if [ -n "${TELEGRAM_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
  echo "BB-Sentinela :: aprovação remota via Telegram ATIVA (aprovar/negar/halt pelo chat)"
else
  echo "BB-Sentinela :: Telegram não configurado — aprovar via 'fosc --approve' (painel/CLI)"
fi

# FOSC_ARGS permite flags extras (ex.: --continuous --interval 3600 --max-items 20).
exec python3 -m fosc.cli -h -a "$TARGET" ${FOSC_ARGS:-}
