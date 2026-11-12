---
inclusion: always
---

# Governança — regras invioláveis do agente

Estas regras valem para QUALQUER código gerado ou alterado neste projeto. Nenhuma
delas pode ser enfraquecida "para funcionar". Se uma tarefa parecer exigir isso,
pare e peça confirmação humana.

## 1. Escopo é determinístico e estrito
- A decisão de escopo é tomada por `fosc/scope.py` (`Scope`), **sem o LLM**. Um
  prompt-injection ou um erro do modelo NÃO pode causar vazamento de escopo.
- Alvo passado como URL (ex. `https://1.migbot.com.br/#/`) = **host exato,
  estrito**: proibido tocar em subdomínio, domínio-pai, domínio-irmão ou qualquer
  outro host. Só se amplia com opt-in explícito do operador.
- Toda ação de rede (recon, request de ferramenta, curl proposto pelo agente) é
  checada em `Scope.allows()` ANTES de sair. Nunca remova esse gate.

## 2. Human-in-the-loop antes de ação sensível
- Ao identificar algo que exige ação mais profunda (scan de banco de dados,
  exploração ativa, qualquer coisa além de recon passivo), o agente **para**,
  **solicita autorização humana autenticada** e **aguarda** a aprovação antes de
  executar. Nunca auto-executa ação sensível.
- A aprovação é autenticada, registrada e vinculada a um responsável.

## 3. Cadeia de custódia (Audit & Evidence)
- Registrar toda requisição, decisão de escopo, aprovação, acesso e evidência com
  timestamp e responsável, de forma auditável e à prova de adulteração.
- Não basta achar a vulnerabilidade: é preciso controlar como o dado foi acessado,
  manipulado, armazenado e usado como evidência.

## 4. LGPD e dados do cliente
- Minimizar exposição de dados pessoais/corporativos. Não coletar nem manipular
  dados além do necessário para comprovar o achado. PoC usa o mínimo suficiente.

## 5. Fila de trabalho que PARA
- A pipeline (recon → rank → hunt → verify → report) é uma fila que pode ser
  **pausada/parada a qualquer momento** (arquivos de controle PAUSE/STOP) e que
  respeita os pontos de aprovação humana acima.

## Mapa dos 4 módulos (arquitetura da palestra)
- **Scope Manager** → `fosc/scope.py` (feito).
- **Authorization Engine** → gate de human-in-the-loop (a fazer).
- **Execution Engine** → `fosc/engine.py` (gated por escopo; falta gate de autorização).
- **Audit & Evidence Manager** → trilha de custódia JSONL (a fazer).
