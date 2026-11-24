.PHONY: start stop test demo build seed clean keys

start:
	docker compose up -d

stop:
	docker compose down

test:
	./lobstertrap/lobstertrap test --policy proxy/policy.yaml
	docker compose exec api sh -c "PYTHONPATH=. pytest tests/"

demo:
	docker compose exec api sh -c "PYTHONPATH=. python tests/run_attacks.py"

build:
	docker compose build

seed:
	docker compose exec api sh -c "PYTHONPATH=. python rbac/seed_namespaces.py"

# Print a fresh SENTINEL_CALLER_KEYS line (one key per role) to paste into .env
keys:
	@python3 -c "import json,secrets; print(\"SENTINEL_CALLER_KEYS='\" + json.dumps({secrets.token_urlsafe(24): r for r in ('admin','analyst','auditor','readonly')}) + \"'\")"

clean:
	rm -rf logs/*.jsonl
	rm -rf data/chromadb/*
	find . -type d -name "__pycache__" -exec rm -rf {} +
