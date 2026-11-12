# Requisitos — Agente de pentest com governança

## Introdução
Um agente autônomo de segurança que executa recon e hunting de vulnerabilidades
**dentro de limites autorizados**, com escopo determinístico, aprovação humana para
ações sensíveis e cadeia de custódia auditável. Alvo de execução: AWS / Kiro.

## Requisitos

### R1 — Contenção de escopo determinística
**História:** Como operador, quero que o agente nunca saia do escopo autorizado,
para não tocar ativos não autorizados do cliente (ex. Banco do Brasil).

Critérios (EARS):
1. QUANDO o alvo é informado como URL, O SISTEMA DEVE tratar o escopo como o host
   exato, rejeitando domínio-pai, irmãos e subdomínios.
2. QUANDO qualquer componente for emitir uma requisição de rede, O SISTEMA DEVE
   validá-la contra o Scope Manager ANTES do envio.
3. A decisão de escopo NÃO DEVE depender do LLM (imune a prompt-injection).
4. QUANDO uma URL está fora de escopo, O SISTEMA DEVE registrar a tentativa com o
   motivo e NÃO executá-la.

### R2 — Cobertura de SPA (achar o que existe)
**História:** Como operador, quero que o agente encontre endpoints de SPAs
(hash-router), para não concluir "sem vulnerabilidades" por falta de superfície.

Critérios:
1. QUANDO um host serve bundles JS, O SISTEMA DEVE minerar caminhos de API
   (`/rest/*`, `/api/*`) desses bundles, dentro do escopo.
2. O SISTEMA DEVE normalizar segmentos dinâmicos (`:id`, `${id}`) para URLs
   testáveis e descartar assets estáticos.

### R3 — Human-in-the-loop (Authorization Engine)
**História:** Como responsável, quero aprovar manualmente ações sensíveis antes da
execução, para manter o controle sobre o que o agente faz.

Critérios:
1. QUANDO o agente identifica uma ação sensível (scan de banco, exploração ativa),
   O SISTEMA DEVE pausar a fila e solicitar autorização humana autenticada.
2. ENQUANTO não houver aprovação, O SISTEMA DEVE NÃO executar a ação.
3. QUANDO a aprovação é concedida, O SISTEMA DEVE registrar quem aprovou, quando e
   o quê, e só então executar.

### R4 — Cadeia de custódia e LGPD (Audit & Evidence)
**História:** Como auditor, quero um registro completo e à prova de adulteração,
para comprovar como cada evidência foi obtida.

Critérios:
1. O SISTEMA DEVE registrar em trilha append-only: requisições, decisões de escopo,
   aprovações, acessos e evidências, com timestamp e responsável.
2. O SISTEMA DEVE minimizar a coleta de dados pessoais ao mínimo necessário para o
   PoC.

### R5 — Fila de trabalho controlável
**História:** Como operador, quero parar/pausar o trabalho a qualquer momento.

Critérios:
1. O SISTEMA DEVE suportar pausar e parar a pipeline entre itens.
2. QUANDO sem internet, O SISTEMA DEVE avisar e não girar silenciosamente.

### R6 — Mapeamento MITRE ATT&CK
**História:** Como analista do BB, quero cada achado mapeado a técnicas ATT&CK.

Critérios:
1. QUANDO um achado é confirmado, O SISTEMA DEVE anexar a(s) técnica(s) ATT&CK
   correspondente(s), de forma determinística, no relatório e na UI.
