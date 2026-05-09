#!/bin/sh
exec /usr/local/bin/lobstertrap serve \
  --policy /etc/lobstertrap/policy.yaml \
  --audit-log /app/logs/audit.jsonl \
  --listen 0.0.0.0:8080 \
  --backend "${BACKEND_URL:-http://localhost:11434}"
