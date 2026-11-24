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

# Print fresh SENTINEL_CALLER_KEYS (one key per role) and LT_AGENT_KEYS (one key per
# agent registered in proxy/policy.yaml) lines to paste into .env
AGENT_IDS := extraction-agent-v1 analysis-agent-v1 critic-agent-v1 action-agent-v1
keys:
	@python3 -c "import json,secrets; print(\"SENTINEL_CALLER_KEYS='\" + json.dumps({secrets.token_urlsafe(24): r for r in ('admin','analyst','auditor','readonly')}) + \"'\")"
	@python3 -c "import json,secrets,sys; print(\"LT_AGENT_KEYS='\" + json.dumps({a: secrets.token_urlsafe(24) for a in sys.argv[1:]}) + \"'\")" $(AGENT_IDS)

clean:
	rm -rf logs/*.jsonl
	rm -rf data/chromadb/*
	find . -type d -name "__pycache__" -exec rm -rf {} +
