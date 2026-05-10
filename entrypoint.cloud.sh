#!/bin/sh
set -e

export LOBSTER_TRAP_URL=http://localhost:8090

echo "[startup] Seeding ChromaDB..."
python /app/rbac/seed_namespaces.py || true

echo "[startup] Starting Lobster Trap on :8090..."
/usr/local/bin/lobstertrap serve \
  --policy /app/proxy/policy.yaml \
  --backend "${LLM_BACKEND_URL:-https://api.groq.com/openai}" \
  --audit-log /app/logs/audit.jsonl \
  --listen 0.0.0.0:8090 &

sleep 2

echo "[startup] Starting FastAPI on :${PORT:-8000}..."
exec uvicorn api.main:app --host 0.0.0.0 --port "${PORT:-8000}"
