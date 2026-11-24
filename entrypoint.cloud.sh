#!/bin/sh
set -e

export LOBSTER_TRAP_URL=http://localhost:8090

# The proxy refuses to start without a key for every agent in proxy/policy.yaml.
: "${LT_AGENT_KEYS:?LT_AGENT_KEYS must be set (JSON agent_id -> key; run make keys)}"

echo "[startup] Seeding ChromaDB..."
python /app/rbac/seed_namespaces.py || true

echo "[startup] Starting Lobster Trap on :8090..."
/usr/local/bin/lobstertrap serve \
  --policy /app/proxy/policy.yaml \
  --backend "${LLM_BACKEND_URL:-https://api.groq.com/openai}" \
  --audit-log /app/logs/audit.jsonl \
  --listen 0.0.0.0:8090 &
PROXY_PID=$!

# Wait for the proxy instead of a fixed sleep; abort if it exits during startup.
for _ in $(seq 1 30); do
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "[startup] Lobster Trap exited during startup; aborting." >&2
    exit 1
  fi
  if python -c "import urllib.request; urllib.request.urlopen('http://localhost:8090/_lobstertrap/', timeout=1)" 2>/dev/null; then
    break
  fi
  sleep 1
done
kill -0 "$PROXY_PID" 2>/dev/null || { echo "[startup] Lobster Trap not running; aborting." >&2; exit 1; }

echo "[startup] Starting FastAPI on :${PORT:-8000}..."
exec uvicorn --factory api.main:create_app --host 0.0.0.0 --port "${PORT:-8000}"
