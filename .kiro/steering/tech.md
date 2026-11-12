---
inclusion: always
---

# Stack e convenções técnicas

## Linguagem e dependências
- **Python 3** (sem framework pesado). Preferir **stdlib**; dependências externas
  só quando necessário (ver `requirements.txt`).
- O agente de IA é o **`claude` CLI** (shell-out headless: `claude -p
  --output-format stream-json ...`). Não há SDK; a orquestração é em Python.
- Ferramentas externas de pentest (subfinder, httpx, katana, nuclei, ffuf, sqlmap,
  dnsx, feroxbuster) são opcionais e detectadas em runtime (`toolrunner.have`).

## Como rodar
- CLI: `bin/fosc` (wrapper) → `python -m fosc.cli`. Flags: `-h` hunt, `-a` alvo,
  `-c` chat, `-v` painel web, `-w` TUI, `-s` status.
- Estado isolado em `~/.bb-sentinela` (override: env **`SENTINELA_HOME`** — usar no
  AWS/Kiro para apontar a um volume persistente).
- Rede: há preflight + watchdog de conectividade (`fosc/net.py`); offline o agente
  avisa em vez de girar.

## Testes
- `python -m pytest -q` (ou `python -m unittest tests.test_core`). O `claude` é
  simulado por `tests/fake_claude.py` — testes rodam **offline e sem custo**.
- Toda mudança em escopo, recon/SPA-mining, MITRE ou governança deve vir com teste.

## Regras de código
- Nada de enfraquecer os gates de governança (ver `governance.md`).
- Determinismo onde importa: escopo e MITRE não dependem do LLM.
- Funções puras e testáveis separadas do IO (ex. `_paths_from_js` vs `js_endpoints`).
