#!/usr/bin/env bash
# BB Sentinela — sobe o painel (viewer) + o despachante da fila num passo só,
# com a fila de caçadas LIGADA (teto global SENTINELA_MAX_HUNTS campanhas
# simultâneas). O viewer enfileira; o despachante lança até o teto e segura o
# resto. Fechar o terminal com Ctrl+C derruba os dois, mas as caçadas já
# lançadas continuam rodando (processos destacados).
#
# Uso:
#   ./start.sh                 # porta 5577, teto 5
#   ./start.sh -p 5580         # outra porta
#   PORT=5580 MAX_HUNTS=3 ./start.sh
#   ./start.sh --stop          # derruba viewer + worker desta porta
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

PORT="${PORT:-5577}"
export SENTINELA_QUEUE=1
export SENTINELA_MAX_HUNTS="${MAX_HUNTS:-5}"

# flags
STOP=0
while [ $# -gt 0 ]; do
  case "$1" in
    -p|--port) PORT="$2"; shift 2 ;;
    --stop)    STOP=1; shift ;;
    *) echo "flag desconhecida: $1" >&2; exit 2 ;;
  esac
done

LOG_DIR="${LOG_DIR:-$HOME/.bb-sentinela/logs}"
mkdir -p "$LOG_DIR"
VIEWER_LOG="$LOG_DIR/viewer-$PORT.log"
WORKER_LOG="$LOG_DIR/worker.log"

# Encerra o viewer que estiver nesta porta (não toca nas caçadas em voo).
kill_viewer() {
  local pid
  pid="$(ss -ltnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | head -1 || true)"
  if [ -n "${pid:-}" ]; then
    kill "$pid" 2>/dev/null || true
    echo "[start] viewer anterior na porta $PORT parado (pid $pid)"
    sleep 1
  fi
}

# Encerra o despachante (fosc --worker). Ele apenas lança caçadas; parar o
# despachante NÃO interrompe as caçadas que já estão rodando.
kill_worker() {
  local pids
  pids="$(pgrep -f 'fosc(\.cli)? .*--worker' || true)"
  if [ -n "${pids:-}" ]; then
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    echo "[start] despachante(s) parado(s): $pids"
  fi
}

if [ "$STOP" = 1 ]; then
  kill_viewer
  kill_worker
  echo "[start] parado. (caçadas já lançadas seguem rodando — use 'bin/fosc --queue' para ver)"
  exit 0
fi

kill_viewer
kill_worker

# Despachante: puxa jobs da fila e lança até SENTINELA_MAX_HUNTS caçadas.
nohup bin/fosc --worker >"$WORKER_LOG" 2>&1 &
WORKER_PID=$!
echo "[start] despachante iniciado (pid $WORKER_PID · teto $SENTINELA_MAX_HUNTS) -> $WORKER_LOG"

# Viewer: painel em 127.0.0.1:$PORT, modo fila (enfileira em vez de lançar direto).
nohup bin/fosc -v -p "$PORT" >"$VIEWER_LOG" 2>&1 &
VIEWER_PID=$!
sleep 2

if ss -ltnp 2>/dev/null | grep -q ":$PORT "; then
  echo "[start] painel no ar: http://127.0.0.1:$PORT/  (pid $VIEWER_PID) -> $VIEWER_LOG"
  echo "[start] fila LIGADA · até $SENTINELA_MAX_HUNTS campanhas simultâneas · um alvo = uma campanha"
  echo "[start] parar tudo: ./start.sh --stop   |   ver a fila: bin/fosc --queue"
else
  echo "[start] ERRO: o viewer não subiu na porta $PORT — veja $VIEWER_LOG" >&2
  cat "$VIEWER_LOG" >&2 || true
  exit 1
fi
