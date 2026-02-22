#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
APP_MODULE="${APP_MODULE:-app.main:app}"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

RUN_DIR="$ROOT_DIR/run"
LOG_DIR="$ROOT_DIR/logs"
PID_FILE="$RUN_DIR/uvicorn.pid"
LOG_FILE="$LOG_DIR/uvicorn.log"

mkdir -p "$RUN_DIR" "$LOG_DIR"

if [[ -d "$VENV_DIR" && -f "$VENV_DIR/bin/activate" ]]; then
  # shellcheck source=/dev/null
  source "$VENV_DIR/bin/activate"
fi

is_running() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ -n "${pid:-}" ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

start() {
  if is_running; then
    echo "Already running (PID: $(cat "$PID_FILE"))."
    exit 0
  fi

  if [[ -f "$PID_FILE" ]]; then
    rm -f "$PID_FILE"
  fi

  nohup "$PYTHON_BIN" -m uvicorn "$APP_MODULE" --host "$HOST" --port "$PORT" >>"$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"

  sleep 1
  if is_running; then
    echo "Started. PID: $(cat "$PID_FILE")"
    echo "Log: $LOG_FILE"
  else
    echo "Failed to start. Check log: $LOG_FILE"
    exit 1
  fi
}

stop() {
  if ! is_running; then
    echo "Not running."
    rm -f "$PID_FILE"
    exit 0
  fi

  local pid
  pid="$(cat "$PID_FILE")"
  kill "$pid" 2>/dev/null || true

  for _ in {1..10}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 1
  done

  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi

  rm -f "$PID_FILE"
  echo "Stopped."
}

status() {
  if is_running; then
    echo "Running (PID: $(cat "$PID_FILE"))."
  else
    echo "Not running."
    exit 1
  fi
}

case "${1:-start}" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    stop || true
    start
    ;;
  status)
    status
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 2
    ;;
esac
