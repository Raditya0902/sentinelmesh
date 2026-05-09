# Context: ChromaDB Namespace Enforcement

## Key Decisions

### NamespacedVectorStore lives in rbac/ not agents/
RBAC enforcement belongs next to the role definitions (`rbac/roles.py`).
Keeping it in `rbac/vector_store.py` means the enforcement logic is co-located with
`can_access_namespace()` and `assert_write_access()`, and agents import from one clear
place instead of a cross-package dependency.

### Permission check happens before any ChromaDB I/O
Both `query()` and `upsert()` call `can_access_namespace()` as the very first line.
No collection is fetched, no embedding is computed until RBAC passes.
This matches the pattern in `orchestrator_node` (RBAC before any LLM call).

### PersistentClient with stable path from env
`CHROMA_PATH` env var, default `./data/chroma/`.
`data/` must be added to `.gitignore` (not already there — add in Phase 1).
The same `NamespacedVectorStore` class works with `HttpClient` by changing the constructor
argument — no caller changes needed when moving to Docker.

### Extraction agent uses vector store context if available
The extraction agent prepends retrieved documents as a `[CONTEXT]` block in its system
prompt. If the vector store raises `PermissionError`, it propagates up; if it returns
empty results, the agent proceeds without context (graceful degradation).

### Seed script uses admin role
`seed_namespaces.py` bypasses nothing — it calls `store.upsert("admin", namespace, ...)`
which passes RBAC for admin. Lets the seeder run through the same enforcement path.

## Key File Paths

| File | Purpose |
|------|---------|
| `rbac/vector_store.py` | NamespacedVectorStore — enforced query/upsert |
| `rbac/seed_namespaces.py` | One-time seed of sample docs per namespace |
| `rbac/roles.py` | Role definitions + can_access_namespace + assert_write_access |
| `agents/extraction.py` | Modified to prepend vector store context |
| `tests/run_attacks.py` | Modified to add cross-namespace attack test |
| `data/chroma/` | ChromaDB persistence directory (gitignored) |

## Environment

```
chromadb:         >=0.5.0 — in requirements.txt, installed
CHROMA_PERSIST_DIR: ./data/chromadb — already in .env and .env.example
Embedding model:  all-MiniLM-L6-v2 (ONNX, cached at ~/.cache/chroma/onnx_models/)
Namespaces:       general, hr, finance, legal, audit
Collections:      sentinelmesh_{namespace} (one per namespace, 17 docs seeded)
```

## Confirmed Behaviour

- [x] Phase 1: `NamespacedVectorStore` raises `PermissionError("Role 'analyst' cannot access namespace 'hr'")` on namespace violation
- [x] Phase 1: `query()` returns `list[dict]` with `id/document/distance/metadata` keys
- [x] Phase 1: write attempt by `readonly` raises `PermissionError("Role 'readonly' does not have write access")`
- [x] Phase 1: empty-collection guard — `query()` returns `[]` instead of crashing when collection has 0 docs
- [x] Phase 1: ONNX embedding model (`all-MiniLM-L6-v2`) downloads once to `~/.cache/chroma/onnx_models/` and is cached
- [x] Phase 2: `seed_namespaces.py` runs idempotently — same counts on second run, no duplicates
- [x] Phase 3: extraction agent prepends `[CONTEXT from knowledge base]` block when docs found; returns "" (no crash) on PermissionError or empty results
- [x] Phase 4: `analyst→hr` query raises `PermissionError("Role 'analyst' cannot access namespace 'hr'")` — caught and reported as PASS
- [x] Phase 4: `readonly` upsert raises `PermissionError("Role 'readonly' does not have write access")` — caught and reported as PASS

## Bugs Found / Fixed

- **Env var name:** Plan said `CHROMA_PATH` but `.env.example`/`.env` already had `CHROMA_PERSIST_DIR=./data/chromadb`. Used `CHROMA_PERSIST_DIR` to avoid divergence.
- **Empty collection crash:** chromadb raises if `n_results` > collection size. Added `count = collection.count()` guard before every `query()` call.

## What's Next After ChromaDB

Per scaffold-tasks.md priority order:
1. Human-review queue (FastAPI endpoint + state in orchestrator)
2. Full adversarial test coverage (10+ attack vectors)
