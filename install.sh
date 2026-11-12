#!/usr/bin/env bash
# BB-Sentinela — instalação via Docker.
#
# Builda a imagem com o ARSENAL completo (recon/enum/nmap/sqlmap/nuclei/...) + o
# claude CLI, e cria o volume de estado persistente. Nada é instalado na máquina
# além da imagem Docker. Uso: bash install.sh
set -euo pipefail

IMAGE="${BB_IMAGE:-bb-sentinela:latest}"
VOLUME="${BB_VOLUME:-bb-sentinela-state}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\033[1;36m[bb-sentinela]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[erro]\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "Docker não encontrado. Instale o Docker e rode de novo."
docker info >/dev/null 2>&1 || die "Docker não está rodando (ou sem permissão). Inicie o daemon (ou use sudo)."

say "buildando ${IMAGE} com o arsenal completo (a 1ª vez demora — compila ferramentas Go e baixa SecLists)..."
docker build -f "${DIR}/deploy/Dockerfile" -t "${IMAGE}" "${DIR}"

say "criando o volume de estado persistente ${VOLUME} (runs/trilha/pocs sobrevivem ao container)..."
docker volume create "${VOLUME}" >/dev/null

say "pronto ✓  imagem '${IMAGE}' e volume '${VOLUME}' criados."
cat <<EOF

────────────────────────────────────────────────────────────────────────
COMO RODAR UMA CAMPANHA (headless)

• Dev / API Anthropic direta (ex.: alvo local OWASP Juice Shop):
    docker run --rm -it --network host \\
      -e SENTINELA_PROVIDER=anthropic -e CLAUDE_CODE_USE_BEDROCK=0 \\
      -e ANTHROPIC_API_KEY \\
      -e TARGET='http://127.0.0.1:3001' \\
      -e SENTINELA_AUTHZ=ask -e SENTINELA_SCOPE_PROXY=1 \\
      -e TELEGRAM_TOKEN -e TELEGRAM_CHAT_ID \\
      -v ${VOLUME}:/data \\
      ${IMAGE}

• Produção / Amazon Bedrock (credenciais AWS no ambiente):
    docker run --rm -it \\
      -e AWS_REGION=us-east-1 -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \\
      -e TARGET='https://alvo-autorizado.com' \\
      -e TELEGRAM_TOKEN -e TELEGRAM_CHAT_ID \\
      -v ${VOLUME}:/data \\
      ${IMAGE}

OPERAR / AUDITAR (o volume guarda tudo):
    # trilha de auditoria (cadeia de custódia, íntegra/violada):
    docker run --rm -v ${VOLUME}:/data --entrypoint fosc ${IMAGE} --audit -a '<TARGET>'
    # aprovar o gate headless (ou use os botões do Telegram):
    docker run --rm -v ${VOLUME}:/data --entrypoint fosc ${IMAGE} --approvals
    # parada de emergência:
    docker run --rm -v ${VOLUME}:/data --entrypoint fosc ${IMAGE} --halt -a '<TARGET>'

Flags extras do hunt via FOSC_ARGS, ex.: -e FOSC_ARGS='--continuous --interval 3600 --max-items 20'
────────────────────────────────────────────────────────────────────────
EOF
