#!/usr/bin/env bash
# Cria a fila SQS FIFO das caçadas do FOSC/TS (idempotente). Rode uma vez por
# ambiente, com credenciais AWS que possam criar filas. Imprime a URL para pôr
# em SENTINELA_SQS_URL (task ECS ou ambiente local).
set -euo pipefail
QUEUE_NAME="${SQS_QUEUE_NAME:-fosc-ts-hunts}.fifo"
REGION="${AWS_REGION:-us-east-1}"

echo "Fila: $QUEUE_NAME  região: $REGION"
URL=$(aws sqs create-queue \
  --queue-name "$QUEUE_NAME" \
  --region "$REGION" \
  --attributes '{
    "FifoQueue": "true",
    "ContentBasedDeduplication": "false",
    "VisibilityTimeout": "3600",
    "MessageRetentionPeriod": "86400",
    "ReceiveMessageWaitTimeSeconds": "10"
  }' \
  --query QueueUrl --output text)

echo "OK. SENTINELA_SQS_URL=$URL"
echo
echo "Próximos passos:"
echo "  1. Ponha essa URL em SENTINELA_SQS_URL na task ECS (deploy/ecs-task-definition.json)."
echo "  2. Garanta a permissão SQS no taskRole (deploy/iam-task-role.json, Sid HuntQueueSQS)."
echo "  3. Suba 1+ worker: contêiner com 'fosc --worker' (lança caçadas da fila)."
echo "     Escale os workers pela métrica ApproximateNumberOfMessagesVisible."
