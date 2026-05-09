# Tasks: ChromaDB Namespace Enforcement

## Checklist

### Phase 1 — NamespacedVectorStore

- [x] Add `data/` to `.gitignore` (already present)
- [x] Add `CHROMA_PERSIST_DIR` to `.env.example` and `.env` (already present as `CHROMA_PERSIST_DIR=./data/chromadb`)
- [x] Create `rbac/vector_store.py` with `NamespacedVectorStore` class
  - [x] `__init__` — reads `CHROMA_PERSIST_DIR` from env, initialises PersistentClient
  - [x] `_collection(namespace)` — get_or_create_collection (DefaultEF auto-used)
  - [x] `query(role_name, namespace, query_text, n_results=5) → list[dict]`
    - [x] `can_access_namespace()` check first — raise PermissionError if denied
    - [x] Guard: returns [] if collection is empty (avoids chromadb n_results error)
    - [x] Returns list of `{id, document, distance, metadata}` dicts
  - [x] `upsert(role_name, namespace, documents, ids, metadatas=None) → None`
    - [x] `can_access_namespace()` check — raise PermissionError if denied
    - [x] `assert_write_access()` check — raise PermissionError if denied
    - [x] Calls `collection.upsert()`

### Phase 2 — Seed script

- [x] Create `rbac/seed_namespaces.py`
  - [x] 4 docs in `general`: remote work policy, Q2 all-hands, project overview, IT security
  - [x] 4 docs in `hr`: salary bands, employee record, performance report, org chart (sensitivity: high)
  - [x] 3 docs in `finance`: budget report, AWS invoice, revenue forecast (sensitivity: high)
  - [x] 3 docs in `legal`: NDA template, vendor contract, GDPR review (sensitivity: medium)
  - [x] 3 docs in `audit`: access log, blocked event, SOC 2 report (sensitivity: medium)
  - [x] Upsert via `store.upsert("admin", namespace, ...)` with stable IDs
  - [x] Prints count per namespace
- [x] Run once — all 5 namespaces seeded, no errors
- [x] Run twice — same counts, no duplicates (idempotent confirmed)
- [x] Query each namespace — semantically correct top result per namespace

### Phase 3 — Wire extraction agent

- [x] Modify `agents/extraction.py`
  - [x] Import `NamespacedVectorStore` from `rbac.vector_store`
  - [x] Add `role` and `namespace` params to `run_extraction()` (defaults: readonly/general)
  - [x] `_fetch_context(role, namespace, query)` helper — instantiates store, queries, formats block
  - [x] If results non-empty, prepends `[CONTEXT from knowledge base]\n- {doc}\n\n` in user prompt
  - [x] If `PermissionError` raised, swallowed in `_fetch_context` → returns "" → proceeds without context
  - [x] If empty results, proceeds without context (no error)
- [x] Modify `orchestrator/main.py` — `extraction_node` now passes `role` and `namespace` to `run_extraction`
- [x] Unit verified: context block format correct, graceful degradation on low-match, PermissionError silently absorbed

### Phase 4 — Attack test hardening

- [x] Modify `tests/run_attacks.py`
  - [x] Add `run_vector_store_test()` helper (matches bool-return pattern of `run_scenario`)
  - [x] `analyst → hr` query: PermissionError raised, message contains "analyst" → PASS
  - [x] `readonly` upsert to general: PermissionError raised, message contains "readonly" → PASS
  - [x] Both tests added to `main()` results — suite is now 3 pipeline + 2 vector store = 5 total
- [x] Vector store tests verified (no Lobster Trap or Ollama required)

### After all phases

- [x] Update `chromadb-context.md` — confirmed behaviours marked, bugs noted
- [x] Update `scaffold-tasks.md` — mark ChromaDB integration `[x]`

## Status: COMPLETE ✅
