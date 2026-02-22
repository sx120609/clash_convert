#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
APP_MODULE="${APP_MODULE:-app.main:app}"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-21502}"
AUTO_INSTALL="${AUTO_INSTALL:-1}"

BASE_PYTHON="$PYTHON_BIN"
VENV_PYTHON="$VENV_DIR/bin/python"

RUN_DIR="$ROOT_DIR/run"
LOG_DIR="$ROOT_DIR/logs"
PID_FILE="$RUN_DIR/uvicorn.pid"
LOG_FILE="$LOG_DIR/uvicorn.log"

mkdir -p "$RUN_DIR" "$LOG_DIR"

ensure_runtime() {
  if [[ "$AUTO_INSTALL" != "1" ]]; then
    return 0
  fi

  if ! command -v "$BASE_PYTHON" >/dev/null 2>&1; then
    echo "Python not found: $BASE_PYTHON"
    exit 1
  fi

  if [[ ! -x "$VENV_PYTHON" ]]; then
    echo "Creating virtualenv at $VENV_DIR ..."
    "$BASE_PYTHON" -m venv "$VENV_DIR"
  fi

  if ! "$VENV_PYTHON" -m pip --version >/dev/null 2>&1; then
    echo "Bootstrapping pip ..."
    "$VENV_PYTHON" -m ensurepip --upgrade
  fi

  if ! "$VENV_PYTHON" -c "import uvicorn, fastapi" >/dev/null 2>&1; then
    echo "Installing dependencies ..."
    "$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel
    "$VENV_PYTHON" -m pip install -e "$ROOT_DIR"
  fi

  PYTHON_BIN="$VENV_PYTHON"
}

is_running() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ -n "${pid:-}" ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

start() {
  ensure_runtime

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

install_only() {
  ensure_runtime
  echo "Dependencies are ready."
}

case "${1:-start}" in
  install)
    install_only
    ;;
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
    echo "Usage: $0 {install|start|stop|restart|status}"
    exit 2
    ;;
esac
