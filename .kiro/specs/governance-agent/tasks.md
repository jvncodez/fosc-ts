# Tarefas — Agente de pentest com governança

Legenda: [x] feito · [ ] a fazer. Cada tarefa referencia o requisito (Rn).

## Feito
- [x] 1. Scope Manager determinístico (`fosc/scope.py`) — estrito p/ alvo-URL,
      `allows()` única fonte de verdade, `note()` sem drift. (R1)
- [x] 2. Centralizar `recon.in_scope` no Scope Manager. (R1)
- [x] 3. Corrigir o vazamento "and its subdomains" no texto de escopo do engine. (R1)
- [x] 4. SPA JS-mining (`_paths_from_js` / `js_endpoints`) + `config.JS_MINING`. (R2)
- [x] 5. Mapeamento MITRE ATT&CK (`fosc/mitre.py`) no finding, report e UI. (R6)
- [x] 6. Detecção de offline (preflight + watchdog) (`fosc/net.py`). (R5)
- [x] 7. Testes offline p/ escopo, SPA mining e MITRE (36 passando).

## Feito (cont.)
- [x] 8. Authorization Engine (human-in-the-loop) (`fosc/authz.py`) (R3)
  - [x] 8.1 Classificar ação passiva x sensível (`risk()`; desconhecido = sensível).
  - [x] 8.2 `ApprovalStore` append-only (request/decision) + `require()` que pausa
        até decidir; gate no início do teste ativo e antes do privesc (`engine.py`).
  - [x] 8.3 Aprovação autenticada (`operator()` + timestamp), headless via
        `fosc --approve/--deny --id <id>` e `fosc --approvals`; interativo via prompt.
  - Modos: `ask` (padrão), `yolo` (lab), `paranoid`. 6 testes.

## A fazer
- [ ] 9. Audit & Evidence Manager (R4)
  - [ ] 9.1 Trilha append-only (req, decisão de escopo, aprovação, evidência).
  - [ ] 9.2 Encadeamento por hash (à prova de adulteração).
  - [ ] 9.3 Minimização de dados pessoais no PoC (LGPD).
- [ ] 10. Enforcement duro de escopo via proxy allowlist (CONNECT/Host). (R1)
- [ ] 11. Validação end-to-end no OWASP Juice Shop (SPA) + checagem anti-fuga. (R1,R2)
- [ ] 12. Integração AWS/Kiro: `SENTINELA_HOME` em volume persistente, segredos
      fora do repo, execução headless com aprovação remota.
- [ ] 13. Rebrand (banner/nome; o pacote interno ainda é `fosc`).

## Como validar
- Offline: `python -m pytest -q`.
- Escopo: um alvo-URL rejeita pai/irmão/subdomínio (ver `tests/test_core.py::ScopeTests`).
- SPA: subir Juice Shop e conferir que a fila sai de ~4 itens para dezenas de rotas.
