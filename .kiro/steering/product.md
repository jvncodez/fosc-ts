---
inclusion: always
---

# Produto — bb-sentinela (Hacka-TS / Banco do Brasil)

Agente autônomo de IA para segurança cibernética, construído para o hackathon do
Banco do Brasil. É uma evolução do FOSC com **governança corporativa**: o
diferencial não é saber fazer pentest, é fazer **dentro de limites autorizados**.

## Para quem
Equipes de segurança que precisam de automação ofensiva (recon → hunt → review →
PoC → relatório) **sem** abrir mão de escopo, autorização, cadeia de custódia e
LGPD. Ambiente-alvo inicial: **AWS**, rodando no **Kiro**.

## Diretriz principal (nunca violar)
Autonomia operacional **não** é autonomia irrestrita. O agente identifica e explora
vulnerabilidades, mas reconhece **quando não tem autorização para continuar** e
**para para pedir intervenção humana**. Encontrar uma vulnerabilidade não é
autorização para explorá-la.

## Estado atual
- Scope Manager determinístico, SPA JS-mining, mapeamento MITRE ATT&CK e detecção
  de offline já implementados (ver `.kiro/specs/governance-agent/tasks.md`).
- A fazer: Authorization Engine (human-in-the-loop), enforcement duro de escopo
  (proxy), Audit & Evidence Manager (cadeia de custódia).
