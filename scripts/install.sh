#!/usr/bin/env bash
#
# FOSC — instalador do zero.
# Monta tudo que o agente precisa: venv Python, dependências, as ferramentas
# de recon (ProjectDiscovery + gau/waybackurls) e verifica a CLI do Claude.
#
# Uso:
#   ./scripts/install.sh            # instala tudo (venv + ferramentas Go)
#   ./scripts/install.sh --no-tools # só o venv Python (ferramentas Go por sua conta)
#
# Testado em Kali/Debian/Ubuntu (WSL2 inclusive). Não roda como root;
# usa sudo apenas para o apt.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

INSTALL_TOOLS=1
[[ "${1:-}" == "--no-tools" ]] && INSTALL_TOOLS=0

say()  { printf '\033[1;31m[fosc]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[fosc]\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# 1. Pré-requisitos de sistema (Python 3.11+, git, Go, curl)
# ---------------------------------------------------------------------------
say "Verificando pré-requisitos do sistema..."
MISSING=()
have python3 || MISSING+=(python3)
have pip3    || MISSING+=(python3-pip)
have git     || MISSING+=(git)
have curl    || MISSING+=(curl)
python3 -c 'import venv' 2>/dev/null || MISSING+=(python3-venv)

if (( ${#MISSING[@]} )); then
  if have apt; then
    say "Instalando via apt: ${MISSING[*]}"
    sudo apt update -y
    sudo apt install -y "${MISSING[@]}"
  else
    warn "Instale manualmente: ${MISSING[*]}"
    exit 1
  fi
fi

PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
say "Python $PYV encontrado."

# ---------------------------------------------------------------------------
# 2. Ambiente virtual Python + dependências
# ---------------------------------------------------------------------------
if [[ ! -d .venv ]]; then
  say "Criando virtualenv em .venv ..."
  python3 -m venv .venv
fi
say "Instalando dependências Python (rich)..."
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt
chmod +x bin/fosc

# ---------------------------------------------------------------------------
# 3. Ferramentas de recon (Go)
# ---------------------------------------------------------------------------
if (( INSTALL_TOOLS )); then
  if ! have go; then
    if have apt; then
      say "Go não encontrado. Instalando golang-go via apt..."
      sudo apt install -y golang-go
    else
      warn "Go não encontrado — instale (https://go.dev/dl) e rode de novo, ou use --no-tools."
      exit 1
    fi
  fi

  export GOBIN="${GOBIN:-$HOME/go/bin}"
  mkdir -p "$GOBIN"
  say "Instalando ferramentas de recon em $GOBIN (pode demorar na 1ª vez)..."

  go_install() { say "  -> $1"; go install "$2" >/dev/null 2>&1 || warn "     falhou: $1 (siga manualmente)"; }
  have subfinder    || go_install subfinder    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  have httpx        || go_install httpx        github.com/projectdiscovery/httpx/cmd/httpx@latest
  have katana       || go_install katana       github.com/projectdiscovery/katana/cmd/katana@latest
  have nuclei       || go_install nuclei       github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  have gau          || go_install gau          github.com/lc/gau/v2/cmd/gau@latest
  have waybackurls  || go_install waybackurls  github.com/tomnomnom/waybackurls@latest

  if have nuclei; then
    say "Atualizando templates do nuclei..."
    "$GOBIN/nuclei" -update-templates -silent >/dev/null 2>&1 || true
  fi

  case ":$PATH:" in
    *":$GOBIN:"*) : ;;
    *) warn "Adicione ao seu ~/.bashrc:  export PATH=\"\$PATH:$GOBIN\"" ;;
  esac
fi

# ---------------------------------------------------------------------------
# 4. CLI do Claude Code (motor do agente) — só verifica
# ---------------------------------------------------------------------------
if have claude; then
  say "Claude CLI: $(claude --version 2>/dev/null || echo presente)"
else
  warn "Claude Code CLI não encontrada no PATH."
  warn "Instale com:  curl -fsSL https://claude.com/install.sh | bash"
  warn "e autentique com:  claude  (uma vez, interativo)."
fi

# ---------------------------------------------------------------------------
# 5. Fim
# ---------------------------------------------------------------------------
say "Pronto. Verifique o ambiente com:"
echo   "    ./scripts/doctor.sh"
say "Exemplo de uso (alvo autorizado):"
echo   "    bin/fosc -h -a alvo.com --max-items 5"
echo   "    bin/fosc -v -p 5555        # painel em http://127.0.0.1:5555"
