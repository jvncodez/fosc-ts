# Prompt para o Kiro — subir todo o stack na AWS

Cole o bloco abaixo no Kiro (dentro deste repositório) para provisionar e rodar
todo o stack na AWS: o motor de caça headless (Fargate + SQS + Bedrock) e o painel
web atrás de API Gateway + Cognito, sem enfraquecer a governança.

Dois pontos dependem de você e o Kiro vai pedir:
1. Solicitar **acesso aos modelos Claude no Bedrock** na região (manual, no console AWS).
2. Definir o **domínio público do painel** e os valores de **VPC/subnets** no `terraform.tfvars`.

---

```
Você é o Kiro trabalhando no repositório bb-sentinela. Objetivo: provisionar e
rodar TODO o stack na AWS — o motor de caça headless (Fargate + SQS + Bedrock) e
o painel web atrás de API Gateway + Cognito — sem enfraquecer a governança.

ANTES DE QUALQUER COISA, leia e trate como fonte da verdade:
- .kiro/steering/infra.md  (Terraform é a única fonte da infra; init→plan→apply)
- .kiro/steering/deploy.md  (convenções: segredos no Secrets Manager, estado no
  EFS, SENTINELA_AUTHZ=ask e SENTINELA_SCOPE_PROXY=1 SEMPRE)
- .kiro/steering/governance.md  (regras invioláveis)
- .kiro/steering/panel-proxy.md  (contrato do painel atrás de Cognito+API Gateway)
- .kiro/specs/aws-authorization/{requirements,design,tasks}.md  (plano oficial)
- deploy/terraform/*  e  deploy/{Dockerfile,entrypoint.sh,README.md}

REGRAS QUE NÃO PODEM SER QUEBRADAS:
1. Provisione SÓ via Terraform (deploy/terraform/). Nada de recurso à mão no
   console nem `aws ... create-*` avulso. Fluxo: terraform init → plan → (eu reviso
   o diff) → apply. Nunca aplique sem me mostrar o plan.
2. Governança no container: SENTINELA_AUTHZ=ask e SENTINELA_SCOPE_PROXY=1. O
   entrypoint recusa `yolo`. Human-in-the-loop obrigatório no gate de teste ativo.
3. Bedrock é autenticado pela task role (sem chaves). Segredos (Telegram) só via
   Secrets Manager. Estado só no EFS (SENTINELA_HOME=/data).
4. Painel: mesma origem para / e /api/* sob SENTINELA_PUBLIC_ORIGIN; preservar os
   headers Origin e X-FOSC nos POST; Cognito no API Gateway; SSE (/api/events) via
   ALB (não pelo timeout de 29s do API Gateway REST); SG da task só aceita o SG do
   ALB; identidade Cognito do operador injetada (X-Operator) para o ledger.

EXECUTE, nesta ordem, parando pra eu aprovar cada `apply`:
A. Pré-checagens (tarefas 0.1–0.3 da spec): me diga o que falta da minha parte —
   acesso aos modelos Claude no Bedrock na região, IAM Identity Center/SSO, e os
   valores de VPC/subnets/allowed_target_cidrs e do domínio público do painel para
   o terraform.tfvars. Gere um terraform.tfvars a partir do .example e me peça os
   valores que faltarem.
B. Imagem: build do deploy/Dockerfile (precisa conter o claude CLI e as ferramentas
   de recon: subfinder, httpx, katana, gau, waybackurls, nuclei, feroxbuster),
   push pro ECR provisionado pelo módulo.
C. Núcleo: terraform init/plan/apply do deploy/terraform/ (ECR, VPC endpoints+SGs,
   EFS, SQS FIFO+DLQ, Secrets, IAM task/execution role, ECS cluster + service do
   worker/dispatcher, CloudWatch Logs). Confirme SENTINELA_QUEUE/ SENTINELA_SQS_URL,
   SENTINELA_MAX_HUNTS=5, AWS_REGION e as envs de governança na task definition.
D. Camada do painel (spec aws-authorization + panel-proxy.md), como Terraform no
   mesmo módulo ou submódulo: Cognito User Pool (app client PKCE, federado ao
   Identity Center), API Gateway HTTP + JWT authorizer, VPC Link → ALB interno →
   serviço Fargate do viewer (fosc.cli -v) em modo proxy com SENTINELA_PUBLIC_ORIGIN;
   DynamoDB de aprovações + Lambdas approval-handler/audit-chain se a spec exigir.
E. Validação (checklist do panel-proxy.md e seção de testes da spec): GET / e
   /api/workspace autenticados → 200; POST /api/approval e /api/halt com Origin
   público + X-FOSC → 200; POST com Origin de outro site → 403; rota sem token
   Cognito → 401 no gateway; SG da task só aceita o SG do ALB; auto-aprovação
   negada. Rode e me mostre os resultados.

No fim, me entregue: a URL pública do painel, o User Pool/app client do Cognito
(como eu faço login), os outputs do Terraform e um resumo do que subiu e do custo
estimado. Não rode nenhuma caçada real ainda — só suba a infra e valide que o
painel autentica e responde.
```
