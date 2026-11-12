# Painel atrás de API Gateway + Cognito — contrato de integração

Como o painel web (viewer `fosc/webview.py`) fica **funcional** quando exposto na
AWS via **API Gateway + Cognito**, sem afrouxar a segurança. O Kiro constrói a
camada de auth (Cognito + API Gateway + authorizer); este doc diz o que essa
camada precisa entregar para o viewer aceitar as requisições.

## Modo de operação do viewer

O viewer tem dois modos, escolhidos pela env `SENTINELA_PUBLIC_ORIGIN`:

| | Single-box (local) | Atrás de proxy (AWS) |
|---|---|---|
| `SENTINELA_PUBLIC_ORIGIN` | vazio | `https://<domínio-do-painel>` |
| bind | `127.0.0.1` | `0.0.0.0` (interface da task) |
| guard de Host | travado em `127.0.0.1/localhost` | confia no proxy (roteamento dele) |
| guard de Origin (CSRF) | `http://127.0.0.1:<porta>` | `== SENTINELA_PUBLIC_ORIGIN` |
| header anti-CSRF `X-FOSC: 1` | **obrigatório** | **obrigatório** |
| autenticação de usuário | — (só localhost) | **Cognito, no API Gateway** |

Local continua idêntico (default). Em produção, basta setar a env na task.

## O que a camada do Kiro DEVE garantir

1. **Autenticação é do Cognito, no API Gateway.** O viewer confia no proxy para
   authn: todo request que chega ao viewer já passou pelo authorizer Cognito
   (JWT). Nenhuma rota do viewer pode ficar exposta sem o authorizer na frente.

2. **Mesma origem para página e API.** Servir `/` (estático da SPA) **e** `/api/*`
   sob o **mesmo** domínio público (`SENTINELA_PUBLIC_ORIGIN`). A SPA chama
   `/api/*` como same-origin; o CSP do viewer é `default-src 'self'`. Domínios
   separados quebram CSP e CORS.

3. **Preservar headers do browser.** A integração HTTP do API Gateway **não pode
   remover** os headers `Origin` e `X-FOSC` nos POST. O front (`api.js`) já envia
   `X-FOSC: 1` e o browser envia `Origin`; ambos são a defesa CSRF do viewer.

4. **Rede.** API Gateway → VPC Link → ALB (interno) → task Fargate na porta do
   viewer. O **Security Group da task** deve permitir ingress **somente do SG do
   ALB** — como o viewer agora binda `0.0.0.0` em modo proxy, o SG é o que o
   isola. Subnets privadas; sem IP público na task.

5. **SSE (`GET /api/events`).** É um stream `text/event-stream` de longa duração.
   API Gateway REST tem timeout de 29s e bufferiza — use **ALB** para essa rota
   (ou HTTP API com timeout estendido), senão o feed ao vivo cai. O polling de
   5s do front funciona mesmo sem SSE, mas o feed ao vivo depende disso.

6. **Ledger de decisões (separação de deveres).** As decisões humanas
   (`POST /api/approval`) e a parada de emergência (`POST /api/halt`) devem
   carregar a identidade Cognito do operador. Hoje o viewer registra
   `operator()` (usuário do SO). O authorizer deve injetar o `sub`/e-mail do
   Cognito (ex.: header `X-Operator`) para o audit trail e o DynamoDB ledger
   amarrarem a decisão ao usuário autenticado — requisito de separação de
   deveres do spec `aws-authorization`.

## Variáveis de ambiente na task (deploy)

```
SENTINELA_PUBLIC_ORIGIN=https://sentinela.<empresa>.com   # liga o modo proxy
SENTINELA_QUEUE=1            # (ou SENTINELA_SQS_URL) fila ligada
SENTINELA_MAX_HUNTS=5        # teto de campanhas simultâneas
AWS_REGION=us-east-1
```

## Checklist de "funcional atrás do proxy"

- [ ] GET `/` e `/api/workspace` autenticados retornam 200 pelo domínio público
- [ ] POST `/api/approval` e `/api/halt` com `Origin` público + `X-FOSC` → 200
- [ ] POST com `Origin` de outro site → 403 (CSRF preservado)
- [ ] rota sem token Cognito → 401 no API Gateway (nunca chega ao viewer)
- [ ] SG da task só aceita o SG do ALB
- [ ] identidade Cognito do operador chega ao viewer para o ledger

> Comprovado localmente simulando o proxy: `SENTINELA_PUBLIC_ORIGIN` setado,
> requisições com Host/Origin do domínio público passam; Origin de outro site e
> POST sem `X-FOSC` seguem bloqueados (403).
