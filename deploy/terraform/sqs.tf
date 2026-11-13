# Fila de caçadas — FIFO, "um alvo uma campanha" (dedup por MessageGroupId=alvo).
# Espelha deploy/setup-sqs.sh e fosc/jobqueue.py (SqsQueue).

resource "aws_sqs_queue" "hunts_dlq" {
  name                        = "${local.name}-hunts-dlq.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  message_retention_seconds   = 1209600 # 14 dias
}

resource "aws_sqs_queue" "hunts" {
  name                        = "${local.name}-hunts.fifo"
  fifo_queue                  = true
  content_based_deduplication = false # dedup explícita por MessageDeduplicationId no código
  deduplication_scope         = "messageGroup"
  fifo_throughput_limit       = "perMessageGroupId"
  visibility_timeout_seconds  = 3600   # = SENTINELA_SQS_VISIBILITY (uma caçada é longa)
  message_retention_seconds   = 345600 # 4 dias
  receive_wait_time_seconds   = 10     # long-poll

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.hunts_dlq.arn
    maxReceiveCount     = 3
  })
}
