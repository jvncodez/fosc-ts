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

## Feito (cont.)
- [x] M. Camada de modelo com failover (`fosc/models.py`) — papel→ladder, provedor
      Anthropic/Bedrock por env (`SENTINELA_PROVIDER`/`BEDROCK_*`), failover em
      falha/recusa/lentidão, custo somado, stream de cada tentativa preservado.
      App pede papel (`models.run`), nunca modelo → trocar modelo é config, não
      código. 6 testes (48 no total). Requisito AWS/Bedrock do BB.

- [x] 9. Audit & Evidence Manager (`fosc/audit.py`) (R4)
  - [x] 9.1 Trilha append-only única (`audit.jsonl`): run_start, scope, plan,
        approval, command/task, finding, halt, run_end. CLI `fosc --audit`.
  - [x] 9.2 Encadeamento por hash SHA-256 (prev+payload); `verify()` acha o 1º elo
        quebrado (à prova de adulteração). Teste de tamper.
  - [x] 9.3 Minimização LGPD (`audit.redact`): mascara email/CPF/cartão; `minimize=`
        aplicado em task/finding.
- [x] 3. Plano do agente antes de cada etapa (`fosc/plan.py`): hipótese/ação/
      resultado esperado/condição de parada, gravado na trilha ANTES de agir. (#3)
- [x] 6. Interrupção de emergência (`fosc --halt`): registro de pgids vivos +
      `kill_all` (SIGKILL in-flight AGORA), arquivo HALT, evidências preservadas. (#6)
- [x] 10. Enforcement DURO de escopo via proxy (`fosc/scope_proxy.py`): forward
      proxy CONNECT+HTTP que só deixa sair hosts em escopo + egress da API; fuga
      bloqueada na REDE (403 + `scope_block` na trilha). Opt-in `SENTINELA_SCOPE_PROXY`.
      Traffic do agente forçado via `claude_runner.PROXY_URL`. (R1) (G0)
- [x] 2b. Tier "proibidas" no Authorization Engine (`_PROHIBITED`): recusa
      determinística, nenhum modo/aprovação habilita. (#2)
- [x] 5b. Campo `confidence` no achado (verify) + no report. (#5)
- [x] 7. Relatório da campanha (`report.write_executive_summary`): resumo executivo
      + índice técnico + integridade da trilha, determinístico. (#7)
- [~] 11. Validação end-to-end no Juice Shop: SPA + anti-fuga feitos; hunt com proxy
      em validação (smoke test com `SENTINELA_SCOPE_PROXY=1`).
- [x] 12. Deploy AWS/Kiro (`deploy/`): Dockerfile (claude CLI + Bedrock + recon),
      entrypoint headless (recusa yolo), ECS Fargate task def com **EFS** p/
      `SENTINELA_HOME` persistente, **Secrets Manager** p/ Telegram (env, fora do
      repo — `notify.telegram_cfg` lê do env), IAM de menor privilégio (Bedrock +
      segredo + EFS + logs), runbook + steering `deploy.md`. Aprovação remota via
      Telegram (já pronta). Falta só: aplicar na conta AWS real.
- [x] 13. Rebrand FOSC→BB-Sentinela (banner/logo ASCII, UI, viewer; pacote interno
      segue `fosc`).
- [x] T. Bot do Telegram (`fosc/telegram_bot.py` + `notify.py`): mão-dupla —
      aprovar/negar o gate por botões inline, `/halt` e `/status`, alertas de ciclo,
      achado com CVSS/confiança/MITRE, `fosc --telegram-test`, segredos via env.

## Como validar
- Offline: `python -m pytest -q`.
- Escopo: um alvo-URL rejeita pai/irmão/subdomínio (ver `tests/test_core.py::ScopeTests`).
- SPA: subir Juice Shop e conferir que a fila sai de ~4 itens para dezenas de rotas.
