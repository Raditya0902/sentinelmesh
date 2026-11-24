.PHONY: start stop test test-policy test-python test-go demo build seed clean keys reset-reviews

start:
	docker compose up -d

stop:
	docker compose down

COV_FAIL_UNDER := 80

test: test-policy test-python

# Policy tests run the binary from the built lobstertrap image against the CURRENT
# proxy/policy.yaml (mounted read-only), so no host Go toolchain or stale host binary.
test-policy:
	docker compose run --rm --no-deps -v "$(CURDIR)/proxy:/policy:ro" \
		--entrypoint lobstertrap lobstertrap test --policy /policy/policy.yaml

test-python:
	docker compose exec api sh -c "PYTHONPATH=. pytest tests/ --cov --cov-fail-under=$(COV_FAIL_UNDER)"

# Needs a host Go toolchain (see lobstertrap/go.mod for the version).
test-go:
	cd lobstertrap && go test ./...

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

# Drop every paused human-review run (checkpoints + review map in the api_data volume).
# Stops the API first so no open connection keeps writing to a deleted file.
reset-reviews:
	docker compose stop api
	docker compose run --rm --no-deps --entrypoint sh api -c "rm -f data/checkpoints.sqlite data/checkpoints.sqlite-wal data/checkpoints.sqlite-shm"
	docker compose start api
