# Design — Agente de pentest com governança

## Visão geral
Pipeline determinística orquestrada em Python, com o `claude` CLI como "cérebro"
para raciocínio ofensivo. Todos os gates de governança são **determinísticos**
(fora do LLM), então nenhuma decisão de segurança depende do modelo se comportar.

```
            ┌──────────────┐
 alvo  ──▶  │ Scope Manager │◀── valida TODA saída de rede (sem LLM)
            └──────┬───────┘
                   ▼
   recon (mecânico + SPA JS-mining)  ──▶  rank  ──▶  fila de trabalho
                   │                                     │
                   ▼                                     ▼
           Authorization Engine  ◀── pausa + aprovação humana p/ ação sensível
                   │
                   ▼
          Execution Engine (hunt) ──▶ verify (Opus) ──▶ report (+MITRE)
                   │
                   ▼
        Audit & Evidence Manager (trilha append-only, cadeia de custódia)
```

## Componentes
- **Scope Manager** (`fosc/scope.py`): `Scope.from_target()` deriva o escopo
  (estrito p/ URL/IP; subdomínios só p/ domínio puro). `allows(url)` é a única
  fonte de verdade; `recon.in_scope` delega a ele. `note()` gera o texto estrito
  entregue ao agente (proíbe drift).
- **Recon / SPA mining** (`fosc/recon.py`): `discover_hosts` só sonda o host em
  escopo; `js_endpoints` baixa bundles JS in-scope e extrai endpoints via
  `_paths_from_js` (função pura, testável). Resultado vira item de hunt.
- **Authorization Engine** (a fazer): classifica a próxima ação (passiva vs
  sensível); se sensível, grava um "pedido de aprovação" no estado, pausa a fila e
  só prossegue quando um responsável autenticado aprova. Mecanismo de aprovação
  compatível com execução headless no AWS/Kiro (ex. aprovação via painel/endpoint
  autenticado, não um prompt bloqueante de terminal).
- **Execution Engine** (`fosc/engine.py`): loop por rodadas, workers paralelos,
  dedup por rota, PAUSE/STOP. Já gated por escopo; falta plugar o gate de autorização.
- **Audit & Evidence Manager** (a fazer): trilha JSONL append-only (idealmente com
  encadeamento por hash p/ ser à prova de adulteração) registrando req, decisão de
  escopo, aprovação, evidência — com timestamp e responsável.
- **MITRE** (`fosc/mitre.py`): mapa determinístico classe→técnica; anexado ao
  finding e ao `report.md`.
- **Net** (`fosc/net.py`): preflight + watchdog de conectividade.

## Enforcement duro de escopo (próximo nível, opcional p/ demo forte)
Proxy local (allowlist por host no CONNECT/Host, sem decifrar TLS) pelo qual TODO
o tráfego das ferramentas passa via `HTTP(S)_PROXY`. Fora do escopo = bloqueado no
nível de rede e logado. Torna o vazamento **impossível**, não só proibido no prompt.

## Decisões
- Governança determinística > confiar no prompt. Prompt reforça, mas não é a barreira.
- Funções puras separadas do IO para testes offline (sem rede, sem custo).
- Estado isolado em `SENTINELA_HOME` para rodar em volume persistente no AWS/Kiro.
