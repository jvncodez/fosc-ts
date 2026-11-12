#!/usr/bin/env bash
# BB-Sentinela — instala o ARSENAL de pentest na máquina local (Debian/Ubuntu/Kali/WSL),
# para o dev local bater com o container de produção (deploy/Dockerfile).
#
# Idempotente e defensivo: pula o que já existe, nunca derruba a máquina.
# Uso: bash scripts/install-tools.sh   (pede sudo para apt)
set -uo pipefail

say() { printf '\033[1;36m[arsenal]\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- apt: portas/serviços, scanners, fingerprint, utilitários ---
if have apt-get; then
  say "apt: nmap masscan nikto whatweb sqlmap wafw00f dnsutils jq git curl wget"
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends \
    nmap masscan nikto whatweb sqlmap wafw00f dnsutils jq git curl wget python3-pip pipx golang-go || true
fi

# --- go: recon/descoberta/fuzzing/exploração web ---
if have go; then
  export PATH="$PATH:$(go env GOPATH)/bin"
  say "go install: subfinder httpx katana nuclei dnsx gau waybackurls assetfinder ffuf gobuster dalfox hakrawler"
  for pkg in \
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    github.com/projectdiscovery/httpx/cmd/httpx@latest \
    github.com/projectdiscovery/katana/cmd/katana@latest \
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    github.com/lc/gau/v2/cmd/gau@latest \
    github.com/tomnomnom/waybackurls@latest \
    github.com/tomnomnom/assetfinder@latest \
    github.com/ffuf/ffuf/v2@latest \
    github.com/OJ/gobuster/v3@latest \
    github.com/hahwul/dalfox/v2@latest \
    github.com/hakluke/hakrawler@latest ; do
    go install "$pkg" 2>/dev/null && say "  ok: ${pkg%%@*}" || say "  falhou: ${pkg%%@*}"
  done
else
  say "go não encontrado — instale golang para as ferramentas PD (subfinder/httpx/nuclei/...)"
fi

# --- feroxbuster (binário) + arjun/dirsearch (python) ---
have feroxbuster || { say "feroxbuster"; curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash -s /usr/local/bin 2>/dev/null || true; }
have arjun || { say "arjun/dirsearch (pip)"; pip3 install --user arjun dirsearch 2>/dev/null || pipx install arjun 2>/dev/null || true; }

# --- SecLists (wordlists usadas por config.CONTENT_WORDLISTS/DNS_WORDLISTS) ---
if [ ! -d /usr/share/seclists ]; then
  say "SecLists (Discovery) -> /usr/share/seclists"
  sudo git clone --depth 1 --filter=blob:none --sparse https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null \
    && sudo git -C /usr/share/seclists sparse-checkout set Discovery 2>/dev/null || true
fi

# nuclei templates
have nuclei && { say "atualizando templates do nuclei"; nuclei -update-templates -silent 2>/dev/null || true; }

say "pronto. Confira o que o agente enxerga:"
echo
python3 - <<'PY' 2>/dev/null || true
from fosc import toolrunner
note = toolrunner.arsenal_note()
print(note or "(nenhuma ferramenta do arsenal no PATH — reabra o shell p/ recarregar o PATH do Go)")
PY
