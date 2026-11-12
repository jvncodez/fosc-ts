---
inclusion: always
---

# Stack e convenções técnicas

## Linguagem e dependências
- **Python 3** (sem framework pesado). Preferir **stdlib**; dependências externas
  só quando necessário (ver `requirements.txt`).
- O agente de IA é o **`claude` CLI** (shell-out headless: `claude -p
  --output-format stream-json ...`). Não há SDK; a orquestração é em Python.
- **Camada de modelo (`fosc/models.py`) — isolamento obrigatório.** A aplicação
  NUNCA nomeia um modelo ou provedor: pede um **papel** (`models.run("hunt"|"verify"|
  "consolidate"|"privesc", ...)`). O router resolve o papel para uma **ladder** de
  modelos candidatos (configuração em `config.MODEL_LADDERS`, sobrescrevível por
  `config.json`/env), escolhe o **provedor** por tentativa (**Anthropic API** ou
  **Amazon Bedrock**, via env `CLAUDE_CODE_USE_BEDROCK` que o CLI já honra) e faz
  **failover** automático se um modelo **falhar, recusar (`status=refused`) ou ficar
  lento** (timeout suave = `MODEL_ATTEMPT_FRACTION` do timeout da tarefa). `offline`
  NÃO faz failover (outro modelo não resolve rede fora). Trocar/adicionar modelo é
  config, não código. **No AWS:** `SENTINELA_PROVIDER=bedrock` + `BEDROCK_SONNET/
  _OPUS/_HAIKU` (inference-profile ids) + credenciais AWS no ambiente.
- `claude_runner.run_claude` é o primitivo de spawn (roda exatamente o modelo que
  recebe); seleção/failover ficam em `models.py`, uma camada acima. Não chamar
  `run_claude` direto da aplicação — usar `models.run(role, ...)`.
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
