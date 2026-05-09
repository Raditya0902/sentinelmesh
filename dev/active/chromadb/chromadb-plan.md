# Plan: ChromaDB Namespace Enforcement

## Goal

Enforce RBAC at the vector store level so that an agent operating under a restricted
role cannot query or write to a namespace it is not permitted to access. This is Demo
Scenario 3: "Analyst tries to access HR namespace → RBAC DENY, logged."

---

## Approach

### Namespace → Collection mapping

Each RBAC namespace maps to one ChromaDB collection:

| Namespace  | Collection name              |
|------------|------------------------------|
| general    | `sentinelmesh_general`       |
| hr         | `sentinelmesh_hr`            |
| finance    | `sentinelmesh_finance`       |
| legal      | `sentinelmesh_legal`         |
| audit      | `sentinelmesh_audit`         |

Collections are created lazily on first access via `get_or_create_collection()`.

### Storage backend

`chromadb.PersistentClient(path=CHROMA_PATH)` where `CHROMA_PATH` defaults to
`./data/chroma/` (gitignored). Swap to `chromadb.HttpClient(host=..., port=...)` for
Docker without changing any caller code.

### Embedding function

Use `chromadb.utils.embedding_functions.DefaultEmbeddingFunction()` (ONNX-based,
bundled with chromadb>=0.5.0). No external service required for embeddings.
`embeddinggemma:latest` (Ollama) could replace this later if semantic quality matters.

---

## Phases

### Phase 1 — `rbac/vector_store.py`: NamespacedVectorStore

Public interface:

```python
class NamespacedVectorStore:
    def query(role_name, namespace, query_text, n_results=5) -> list[dict]
    def upsert(role_name, namespace, documents, ids, metadatas=None) -> None
```

RBAC enforcement:
- Both methods call `can_access_namespace(role_name, namespace)` first.
- `upsert` additionally calls `assert_write_access(role_name)`.
- Violations raise `PermissionError` with `role_name` and `namespace` in the message.
- No ChromaDB I/O happens before the permission check passes.

Return shape for `query`:
```python
[{"id": str, "document": str, "distance": float, "metadata": dict}, ...]
```

### Phase 2 — `rbac/seed_namespaces.py`: Seed script

- Idempotent: upsert with stable IDs → safe to re-run.
- Seeds 3–5 documents per namespace with distinct sensitivity metadata.
- Role used for seeding: `admin` (full access).
- Run: `PYTHONPATH=. python rbac/seed_namespaces.py`

### Phase 3 — Wire extraction agent

In `agents/extraction.py`:
- Import `NamespacedVectorStore` from `rbac.vector_store`.
- Before the LLM call, query the store with the user's task as the query text.
- Prepend retrieved docs as `[CONTEXT]` block in the system prompt.
- `PermissionError` from the store propagates to `orchestrator_node` which catches it
  and sets `state["blocked"] = True`.

### Phase 4 — Attack test hardening

In `tests/run_attacks.py`:
- Add explicit `NamespacedVectorStore` cross-namespace test.
- Call `store.query("analyst", "hr", "salary data")`.
- Assert `PermissionError` is raised.
- Assert error message contains both `analyst` and `hr`.

---

## Trade-offs

| Decision | Chosen | Alternative | Why |
|----------|--------|-------------|-----|
| Storage | PersistentClient (embedded) | HttpClient | simpler for dev; same interface for Docker |
| Embedding | DefaultEmbeddingFunction | Ollama embeddinggemma | no extra service dep; swap later if needed |
| Collection naming | `sentinelmesh_{ns}` | bare namespace name | avoids collision with other ChromaDB users |
| Seed location | `rbac/seed_namespaces.py` | fixture in tests | lets humans re-seed without running tests |

---

## Files Owned by Claude (this feature)

| File | Action |
|------|--------|
| `rbac/vector_store.py` | CREATE — NamespacedVectorStore |
| `rbac/seed_namespaces.py` | CREATE — seed script |
| `agents/extraction.py` | MODIFY — prepend vector store context |
| `tests/run_attacks.py` | MODIFY — add cross-namespace attack test |
| `.env.example` | MODIFY — add CHROMA_PATH |
| `.gitignore` | MODIFY — add data/ |

Not touched (Gemini-owned): `dashboard/`, `docker-compose.yml`, `Makefile`.
