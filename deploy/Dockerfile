# BB-Sentinela — container de execução headless (AWS Fargate + Bedrock) com o
# ARSENAL de pentest completo (recon, enumeração, portas, fuzzing, exploração).
#
# Não contém segredos: token do Telegram e ids de modelo chegam por env (Secrets
# Manager). O estado (SENTINELA_HOME) fica num volume EFS, fora da imagem.
#
# ATENÇÃO (escopo): nmap/masscan fazem TCP cru e NÃO passam pelo proxy de escopo
# (que é HTTP/CONNECT). Em produção, restrinja a saída do container no nível de
# rede (security group / NACL) aos IPs do alvo. Ver .kiro/steering/deploy.md.

# --- estágio 1: ferramentas em Go ---
FROM golang:1.23-bookworm AS gotools
ENV GOBIN=/out
RUN mkdir -p /out && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/hakluke/hakrawler@latest

# --- estágio 2: imagem final (node p/ o claude CLI + python + arsenal apt) ---
FROM node:22-bookworm-slim

# Arsenal via apt: portas/serviços, scanners, exploração, fingerprint, utilitários.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip pipx ca-certificates git curl wget jq openssl \
      nmap masscan nikto whatweb sqlmap wafw00f dnsutils \
 && rm -rf /var/lib/apt/lists/*

# Claude Code CLI (o agente shell-out). Bedrock é ligado por env, não aqui.
RUN npm install -g @anthropic-ai/claude-code

# ferramentas Go do estágio anterior
COPY --from=gotools /out/ /usr/local/bin/

# feroxbuster (binário oficial) + descoberta de parâmetros/diretórios em python
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin \
 && pip3 install --no-cache-dir --break-system-packages arjun dirsearch

# wordlists (SecLists/Discovery — o que config.CONTENT_WORDLISTS/DNS_WORDLISTS usa)
RUN git clone --depth 1 --filter=blob:none --sparse https://github.com/danielmiessler/SecLists.git /usr/share/seclists \
 && git -C /usr/share/seclists sparse-checkout set Discovery \
 && ln -s /usr/share/seclists /usr/share/wordlists 2>/dev/null || true

# templates do nuclei (atualiza no build; re-atualiza em runtime se houver rede)
RUN nuclei -update-templates -silent || true

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt
COPY fosc ./fosc
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Defaults de governança para produção (sobrescrevíveis pela task definition).
ENV SENTINELA_HOME=/data \
    SENTINELA_PROVIDER=bedrock \
    SENTINELA_AUTHZ=ask \
    SENTINELA_SCOPE_PROXY=1 \
    CLAUDE_CODE_USE_BEDROCK=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
