#!/usr/bin/env bash
# FOSC — checagem de ambiente. Diz o que está pronto e o que falta.
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ok()   { printf '  \033[1;32m ok  \033[0m  %-14s %s\n' "$1" "${2:-}"; }
miss() { printf '  \033[1;31mmiss \033[0m  %-14s %s\n' "$1" "${2:-}"; }
chk()  { if command -v "$1" >/dev/null 2>&1; then ok "$1" "$("$1" --version 2>/dev/null | head -1)"; else miss "$1" "${2:-}"; fi; }

echo "FOSC doctor"
echo "Python:"
if [[ -x .venv/bin/python ]]; then ok ".venv" "$(.venv/bin/python --version)"; else miss ".venv" "rode scripts/install.sh"; fi
.venv/bin/python -c 'import rich' 2>/dev/null && ok "rich" || miss "rich" "pip install -r requirements.txt"

echo "Motor:"
chk claude "instale: curl -fsSL https://claude.com/install.sh | bash"

echo "Recon (opcionais — o que faltar é só pulado):"
for t in subfinder httpx katana nuclei gau waybackurls; do chk "$t" "go install ..."; done

echo
echo "Teste offline (não gasta API):  .venv/bin/python -m unittest tests.test_core"
