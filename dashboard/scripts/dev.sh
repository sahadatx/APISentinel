#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ -n "${APISENTINEL_PYTHON:-}" ]]; then
  PYTHON_BIN="$APISENTINEL_PYTHON"
elif [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  PYTHON_BIN="$VIRTUAL_ENV/bin/python"
elif [[ -x "$PROJECT_ROOT/.venv/bin/python" ]]; then
  PYTHON_BIN="$PROJECT_ROOT/.venv/bin/python"
else
  PYTHON_BIN="python"
fi
API_PORT="${APISENTINEL_API_PORT:-8001}"
CUSTOM_API_PROXY="${APISENTINEL_API_PROXY:-}"
API_PROXY="${CUSTOM_API_PROXY:-http://127.0.0.1:${API_PORT}}"
READY_URL="${API_PROXY%/}/api/v1/ready"
API_PID=""
WORKER_PID=""
export APISENTINEL_API_PROXY="$API_PROXY"

cleanup() {
  if [[ -n "$WORKER_PID" ]] && kill -0 "$WORKER_PID" 2>/dev/null; then
    kill "$WORKER_PID" 2>/dev/null || true
    wait "$WORKER_PID" 2>/dev/null || true
  fi
  if [[ -n "$API_PID" ]] && kill -0 "$API_PID" 2>/dev/null; then
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
}

is_ready() {
  READY_URL="$READY_URL" python - <<'PY'
import os
import urllib.request
try:
    with urllib.request.urlopen(os.environ["READY_URL"], timeout=1) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except Exception:
    raise SystemExit(1)
PY
}

if ! is_ready; then
  if [[ -n "$CUSTOM_API_PROXY" ]]; then
    echo "Configured API proxy is unavailable: ${API_PROXY}" >&2
    exit 1
  fi
  cd "$PROJECT_ROOT"
  PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" \
    "$PYTHON_BIN" -m uvicorn apisentinel.main:app --host 127.0.0.1 --port "$API_PORT" &
  API_PID=$!
  trap cleanup EXIT INT TERM
  for _ in $(seq 1 30); do
    if is_ready; then break; fi
    if ! kill -0 "$API_PID" 2>/dev/null; then
      echo "APISentinel API stopped before readiness. Check database configuration and migrations." >&2
      exit 1
    fi
    sleep 1
  done
  if ! is_ready; then
    echo "APISentinel API did not become ready at ${READY_URL}. Check database configuration and migrations." >&2
    exit 1
  fi
fi

# A local API accepts work into the shared database, so its development UI also
# needs a consumer. Never start a worker for a custom API proxy: that proxy may
# point to a database this process must not touch.
if [[ -z "$CUSTOM_API_PROXY" ]]; then
  cd "$PROJECT_ROOT"
  PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" \
    "$PYTHON_BIN" -c 'import os; from apisentinel.job_queue import worker_loop; worker_loop(f"local-dev-{os.getpid()}", 1.0)' &
  WORKER_PID=$!
  trap cleanup EXIT INT TERM
  sleep 0.2
  if ! kill -0 "$WORKER_PID" 2>/dev/null; then
    echo "APISentinel local queue worker did not start. Check Python and database configuration." >&2
    exit 1
  fi
  echo "APISentinel local queue worker started. Active HTTP execution still follows APISENTINEL_ALLOW_ACTIVE_TESTS."
else
  echo "Using a custom API proxy; local queue worker was not started. Configure the worker beside that API."
fi

cd "$PROJECT_ROOT/dashboard"
npm run dev:frontend
