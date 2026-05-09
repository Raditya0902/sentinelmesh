.PHONY: start stop test demo build seed clean

start:
	docker compose up -d

stop:
	docker compose down

test:
	./lobstertrap/lobstertrap test --policy proxy/policy.yaml
	docker compose exec api sh -c "PYTHONPATH=. pytest tests/test_rbac.py tests/test_pipeline.py"

demo:
	docker compose exec api sh -c "PYTHONPATH=. python tests/run_attacks.py"

build:
	docker compose build

seed:
	docker compose exec api sh -c "PYTHONPATH=. python rbac/seed_namespaces.py"

clean:
	rm -rf logs/*.jsonl
	rm -rf data/chromadb/*
	find . -type d -name "__pycache__" -exec rm -rf {} +
