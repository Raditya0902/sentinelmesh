# Plan: Human-Review Queue

## Goal

Surface items that Lobster Trap flags as `HUMAN_REVIEW` in a queryable queue, and
allow a reviewer to approve or reject each item via the API. The dashboard (Gemini task)
can then read `GET /review/queue` to show pending items with a red badge.

---

## What Lobster Trap already does

The `human_review_mismatch` rule in `proxy/policy.yaml` fires `HUMAN_REVIEW` when
`risk_score` is 0.5–0.8. Unlike `DENY`, `HUMAN_REVIEW` **passes the request through**
(no deny_message) but writes the flagged entry to the audit log (`logs/audit.jsonl`)
with `action: HUMAN_REVIEW`. There is no in-band signal to the Python caller — the
LLM response content is normal; only the audit log entry reveals the flag.

## Architecture

```
Lobster Trap
  └── writes HUMAN_REVIEW entry → logs/audit.jsonl

GET /review/queue
  └── scans audit.jsonl for action == HUMAN_REVIEW
  └── cross-references logs/review_decisions.jsonl
  └── returns: pending / approved / rejected items

POST /review/{request_id}/decide  {decision, note}
  └── appends to logs/review_decisions.jsonl
  └── returns: ReviewItem with decision filled in
```

## Storage

Two JSONL files, both under `logs/` (already gitignored for `*.jsonl`):

| File | Writer | Reader |
|------|--------|--------|
| `logs/audit.jsonl` | Lobster Trap | `GET /audit`, `GET /review/queue` |
| `logs/review_decisions.jsonl` | `POST /review/{id}/decide` | `GET /review/queue` |

No database, no new service. Same file-tail pattern as the existing `/audit` endpoint.

---

## Phases

### Phase 1 — Schemas

New Pydantic models in `api/main.py`:

```python
class ReviewDecision(BaseModel):
    decision: Literal["approve", "reject"]
    note: str = ""

class ReviewItem(BaseModel):
    request_id: str
    timestamp: str
    agent_id: str
    risk_score: float
    rule_name: str
    raw: dict          # full audit entry for dashboard use
    decision: str | None   # None = pending
    note: str
```

### Phase 2 — `GET /review/queue`

Query param: `status: "pending" | "approved" | "rejected" | "all"` (default: `"pending"`)

Logic:
1. Read audit log, filter entries where `action == "HUMAN_REVIEW"`
2. Read `logs/review_decisions.jsonl`, build `{request_id → decision}` map
3. Join on `request_id`, apply status filter
4. Return list of `ReviewItem`

### Phase 3 — `POST /review/{request_id}/decide`

1. Validate `request_id` exists in audit log with `action == HUMAN_REVIEW`
2. Reject if already decided (idempotent read, error on re-decision)
3. Append `{request_id, decision, note, decided_at}` to `logs/review_decisions.jsonl`
4. Return the completed `ReviewItem`

---

## Trade-offs

| Decision | Chosen | Alternative | Why |
|----------|--------|-------------|-----|
| Storage | JSONL files | SQLite / Redis | matches audit log pattern; no new dep |
| Re-decision | Error (409) | Overwrite | prevents accidental re-approval; simpler audit trail |
| AgentState | Unchanged | Add `human_review: bool` | detection requires reading audit log post-run; adds complexity for no demo gain |
| Queue scan | Full file scan on each request | Index/cache | acceptable for hackathon demo volumes |

---

## Files Owned by Claude (this feature)

| File | Action |
|------|--------|
| `api/main.py` | MODIFY — add schemas + 2 endpoints |

Not touched: orchestrator, agents, rbac, dashboard (Gemini extends dashboard).
