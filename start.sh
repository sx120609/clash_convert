#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
APP_MODULE="${APP_MODULE:-app.main:app}"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-21502}"
AUTO_INSTALL="${AUTO_INSTALL:-1}"
VENV_CREATOR="${VENV_CREATOR:-auto}"
MIN_PYTHON_MINOR="${MIN_PYTHON_MINOR:-10}"

if [[ "$PYTHON_BIN" == "python3" ]]; then
  for cand in python3.12 python3.11 python3.10 python3; do
    if command -v "$cand" >/dev/null 2>&1; then
      PYTHON_BIN="$cand"
      break
    fi
  done
fi

BASE_PYTHON="$PYTHON_BIN"
VENV_PYTHON="$VENV_DIR/bin/python"
VENV_TOOL=""

RUN_DIR="$ROOT_DIR/run"
LOG_DIR="$ROOT_DIR/logs"
PID_FILE="$RUN_DIR/uvicorn.pid"
LOG_FILE="$LOG_DIR/uvicorn.log"

mkdir -p "$RUN_DIR" "$LOG_DIR"
cd "$ROOT_DIR"

fix_debian_apt_sources() {
  shopt -s nullglob
  local files=(/etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources)
  local f backup_dir ts backup_name

  echo "Trying to fix deprecated Debian source entries ..."
  backup_dir="/tmp/startsh-apt-backup"
  mkdir -p "$backup_dir"
  ts="$(date +%s)"

  # Cleanup old backups accidentally created in sources.list.d by earlier script versions.
  find /etc/apt/sources.list.d -maxdepth 1 -type f -name "*.bak.*" -delete 2>/dev/null || true

  for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    backup_name="$(echo "$f" | sed 's#/#_#g')"
    cp "$f" "$backup_dir/${backup_name}.${ts}.bak" || true

    if [[ "$f" == *.sources ]]; then
      # deb822-style sources
      sed -i -E \
        's#^([[:space:]]*URIs:[[:space:]]*)https?://security\.debian\.org([[:space:]]*)$#\1http://security.debian.org/debian-security\2#g' \
        "$f"
      sed -i -E \
        '/^[[:space:]]*Suites:[[:space:]]*/ s/\bbullseye\/updates\b/bullseye-security/g' \
        "$f"
      # Drop bullseye-backports token from Suites.
      sed -i -E \
        '/^[[:space:]]*Suites:[[:space:]]*/ { s/\bbullseye-backports\b//g; s/[[:space:]]+/ /g; s/[[:space:]]+$//g; }' \
        "$f"
    else
      # legacy .list-style sources
      sed -i -E \
        's#^([[:space:]]*deb(-src)?([[:space:]]+\[[^]]+\])?[[:space:]]+https?://security\.debian\.org)(/debian-security)?[[:space:]]+bullseye/updates([[:space:]].*)$#\1/debian-security bullseye-security\5#g' \
        "$f"
      # Disable broken bullseye-backports entries.
      sed -i -E \
        '/^[[:space:]]*deb(-src)?([[:space:]]+\[[^]]+\])?[[:space:]]+.*bullseye-backports/ s/^/# disabled by start.sh: /' \
        "$f"
    fi
  done

  echo "APT source backups saved to: $backup_dir"
}

apt_update_with_retry() {
  if apt-get update -y; then
    return 0
  fi

  fix_debian_apt_sources
  if apt-get update -y; then
    return 0
  fi

  echo "apt-get update still failed after auto-fix."
  echo "Please check files under /etc/apt/sources.list and /etc/apt/sources.list.d/."
  return 1
}

bootstrap_system_pip() {
  if "$BASE_PYTHON" -m pip --version >/dev/null 2>&1; then
    return 0
  fi

  local tmp
  tmp="$(mktemp /tmp/get-pip.XXXXXX.py)"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$tmp"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmp" https://bootstrap.pypa.io/get-pip.py
  else
    rm -f "$tmp"
    return 1
  fi

  "$BASE_PYTHON" "$tmp" --disable-pip-version-check
  rm -f "$tmp"
  "$BASE_PYTHON" -m pip --version >/dev/null 2>&1
}

ensure_venv_support() {
  if [[ "$VENV_CREATOR" == "venv" || "$VENV_CREATOR" == "auto" ]]; then
    if "$BASE_PYTHON" -c "import ensurepip" >/dev/null 2>&1; then
      VENV_TOOL="venv"
      return 0
    fi
  fi

  if [[ "$VENV_CREATOR" == "virtualenv" || "$VENV_CREATOR" == "auto" ]]; then
    if command -v virtualenv >/dev/null 2>&1; then
      VENV_TOOL="virtualenv-bin"
      return 0
    fi

    if "$BASE_PYTHON" -m virtualenv --version >/dev/null 2>&1; then
      VENV_TOOL="virtualenv-module"
      return 0
    fi

    echo "ensurepip unavailable, trying virtualenv fallback ..."
    if ! bootstrap_system_pip; then
      echo "Cannot bootstrap pip with get-pip.py."
    else
      "$BASE_PYTHON" -m pip install --upgrade pip virtualenv || true
      if "$BASE_PYTHON" -m virtualenv --version >/dev/null 2>&1; then
        VENV_TOOL="virtualenv-module"
        return 0
      fi
    fi
  fi

  echo "Missing Python venv support (ensurepip)."

  if command -v apt-get >/dev/null 2>&1; then
    local py_ver
    py_ver="$("$BASE_PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)"

    if [[ "$(id -u)" -ne 0 ]]; then
      echo "Please run as root (or use sudo): apt-get update && apt-get install -y python3-venv"
      exit 1
    fi

    echo "Installing system package: python3-venv ..."
    export DEBIAN_FRONTEND=noninteractive
    apt_update_with_retry
    apt-get install -y python3-venv || true
    if [[ -n "$py_ver" ]]; then
      apt-get install -y "python${py_ver}-venv" || true
    fi
  else
    echo "Cannot auto-install venv support. Install python3-venv manually."
    exit 1
  fi

  if "$BASE_PYTHON" -c "import ensurepip" >/dev/null 2>&1; then
    VENV_TOOL="venv"
    return 0
  fi

  echo "python3-venv installed, but ensurepip is still unavailable."
  echo "Try installing version-specific package, e.g. python3.11-venv."
  if [[ -z "$VENV_TOOL" ]]; then
    exit 1
  fi
}

recreate_venv() {
  ensure_venv_support
  rm -rf "$VENV_DIR"
  echo "Creating virtualenv at $VENV_DIR (tool: $VENV_TOOL) ..."

  case "$VENV_TOOL" in
    venv)
      "$BASE_PYTHON" -m venv "$VENV_DIR"
      ;;
    virtualenv-bin)
      virtualenv -p "$BASE_PYTHON" "$VENV_DIR"
      ;;
    virtualenv-module)
      "$BASE_PYTHON" -m virtualenv "$VENV_DIR"
      ;;
    *)
      echo "No available virtual environment tool."
      exit 1
      ;;
  esac
}

install_runtime_deps() {
  echo "Installing runtime dependencies from pyproject.toml ..."
  "$VENV_PYTHON" - <<'PY'
import pathlib
import subprocess
import sys

pyproject = pathlib.Path("pyproject.toml")
if not pyproject.exists():
    raise SystemExit("pyproject.toml not found")

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-user", "tomli"])
        import tomli as tomllib

data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
deps = data.get("project", {}).get("dependencies", [])
if not deps:
    print("No dependencies declared in pyproject.toml.")
    raise SystemExit(0)

cmd = [sys.executable, "-m", "pip", "install", "--no-user", *deps]
print("Running:", " ".join(cmd))
subprocess.check_call(cmd)
PY
}

ensure_runtime() {
  if [[ "$AUTO_INSTALL" != "1" ]]; then
    return 0
  fi

  if ! command -v "$BASE_PYTHON" >/dev/null 2>&1; then
    echo "Python not found: $BASE_PYTHON"
    exit 1
  fi

  local py_minor
  py_minor="$("$BASE_PYTHON" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo 0)"
  if [[ "$py_minor" -lt "$MIN_PYTHON_MINOR" ]]; then
    echo "Python $("$BASE_PYTHON" -V 2>&1) is too old for this project."
    echo "Current code requires Python >= 3.${MIN_PYTHON_MINOR}."
    echo "Set PYTHON_BIN to a newer interpreter, e.g.: PYTHON_BIN=python3.11 bash start.sh"
    exit 1
  fi

  if [[ ! -x "$VENV_PYTHON" ]]; then
    recreate_venv
  fi

  if ! "$VENV_PYTHON" -m pip --version >/dev/null 2>&1; then
    echo "Virtualenv is missing pip. Rebuilding virtualenv ..."
    recreate_venv
  fi

  if ! "$VENV_PYTHON" -m pip --version >/dev/null 2>&1; then
    echo "pip is still unavailable inside $VENV_DIR."
    echo "Please run: apt-get update && apt-get install -y python3-venv python3-pip"
    exit 1
  fi

  if ! "$VENV_PYTHON" -c "import uvicorn, fastapi" >/dev/null 2>&1; then
    echo "Installing dependencies ..."
    "$VENV_PYTHON" -m pip install --no-user --upgrade pip setuptools wheel
    install_runtime_deps
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

case "${1:-restart}" in
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
    echo "Usage: $0 {install|start|stop|restart|status} (default: restart)"
    exit 2
    ;;
esac
