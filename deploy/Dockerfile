# BB-Sentinela — container de execução headless (AWS Fargate + Bedrock).
#
# Empacota o agente + o `claude` CLI em modo Bedrock + as ferramentas de recon.
# Não contém segredos: token do Telegram e ids de modelo chegam por env (Secrets
# Manager). O estado (SENTINELA_HOME) fica num volume EFS, fora da imagem.

# --- ferramentas de recon (ProjectDiscovery), compiladas num estágio separado ---
FROM golang:1.23-bookworm AS tools
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# --- imagem final: node (p/ o claude CLI) + python ---
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates git curl \
 && rm -rf /var/lib/apt/lists/*

# Claude Code CLI (o agente shell-out). Bedrock é ligado por env, não aqui.
RUN npm install -g @anthropic-ai/claude-code

# ferramentas de recon do estágio anterior
COPY --from=tools /go/bin/httpx /go/bin/katana /go/bin/nuclei /go/bin/subfinder /go/bin/dnsx /usr/local/bin/

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt
COPY fosc ./fosc
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Defaults de governança para produção (sobrescrevíveis pela task definition).
# O estado é um volume; o provedor é Bedrock; o proxy de escopo é obrigatório;
# a autorização é 'ask' (human-in-the-loop) — nunca 'yolo' em produção.
ENV SENTINELA_HOME=/data \
    SENTINELA_PROVIDER=bedrock \
    SENTINELA_AUTHZ=ask \
    SENTINELA_SCOPE_PROXY=1 \
    CLAUDE_CODE_USE_BEDROCK=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
