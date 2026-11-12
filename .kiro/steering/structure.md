---
inclusion: always
---

# Estrutura do projeto

```
bin/fosc              wrapper de CLI -> python -m fosc.cli
fosc/
  cli.py              parsing de flags e dispatch
  engine.py           Execution Engine: loop recon -> rank -> hunt -> verify -> report
  scope.py            Scope Manager determinístico (barreira de escopo, sem LLM)
  recon.py            recon mecânico + SPA JS-mining (_paths_from_js / js_endpoints)
  rank.py             priorização de endpoints
  prompts.py          system prompts + schemas (hunt/verify/privesc/consolidate)
  claude_runner.py    spawn do `claude` headless + stream-json + watchdog de rede
  verify.py           revisão adversarial (Opus) antes de "confirmed"
  privesc.py          fase pós-RCE (multi-pass) — enumeração e escalonamento
  mitre.py            mapa determinístico classe de vuln -> MITRE ATT&CK
  net.py              sonda de conectividade (preflight + watchdog)
  knowledge.py        aprendizado entre caçadas (~/.bb-sentinela/knowledge)
  report.py           report.md por achado (inclui seção MITRE ATT&CK)
  notify.py           Telegram (opcional)
  ui.py / tui.py / banner.py / thinking.py / composer.py   terminal
  web/ + webview.py   painel web local (127.0.0.1)
  state.py            estado persistido por alvo (~/.bb-sentinela/runs/<alvo>)
tests/                testes offline (fake_claude.py simula o `claude`)
.kiro/                steering (regras) + specs (spec-driven do Kiro)
```

## Onde mexer para cada coisa
- Regra/decisão de escopo → `scope.py` (nunca espalhar lógica de escopo por aí).
- Achar mais endpoints (SPA/API) → `recon.py` (`_paths_from_js`, `js_endpoints`).
- Tag MITRE → `mitre.py`.
- Novo gate de governança (human-in-the-loop, audit) → módulo novo + `engine.py`.
- Fluxo da fila / pausa-parada → `engine.py` + `state.py` (PAUSE/STOP).
