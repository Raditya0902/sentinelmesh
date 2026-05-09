# Context: Human-Review Queue

## Key Decisions

### Queue is audit-log-derived, not orchestrator-driven
`HUMAN_REVIEW` from Lobster Trap passes the request through (no deny_message). The only
record is in the audit log. Trying to detect it in the orchestrator would require either
parsing LLM response content (fragile) or reading the audit log after each run (racy).
Correct answer: the queue lives entirely at the API layer — `GET /review/queue` scans
the audit log and returns flagged items. No AgentState changes.

### Decisions persisted in a separate JSONL file
Writing decisions back into the audit log would contaminate a Lobster Trap-owned file.
A separate `logs/review_decisions.jsonl` keeps concerns clean:
- Lobster Trap owns `audit.jsonl`
- Our API owns `review_decisions.jsonl`
Both are under `logs/` which is already gitignored for `*.jsonl`.

### Re-decision returns 409
If a `request_id` has already been decided, `POST /review/{id}/decide` returns HTTP 409.
This prevents accidental double-approval and keeps the decisions file append-only/clean.

### audit.jsonl field names
Exact field names depend on what Lobster Trap writes. The queue endpoint uses `.get()`
with safe defaults so it doesn't crash on missing fields. Known fields from GEMINI.md
dashboard spec: `request_id`, `verdict`, `action`, `rule_name`, `risk_score`,
`agent_id`, `declared_intent`, `intent_category`.

## Key File Paths

| File | Purpose |
|------|---------|
| `api/main.py` | FastAPI app — modified to add 2 new endpoints + schemas |
| `logs/audit.jsonl` | Lobster Trap audit log — source of HUMAN_REVIEW entries |
| `logs/review_decisions.jsonl` | API-written decisions (approve/reject + note) |

## Environment

```
AUDIT_LOG_PATH:    logs/audit.jsonl (already in .env)
REVIEW_QUEUE_PATH: logs/review_decisions.jsonl (new, derived from AUDIT_LOG_PATH dir)
```

No new env var needed — `review_decisions.jsonl` lives in the same dir as `audit.jsonl`.

## HUMAN_REVIEW Trigger Mechanism (how it actually fires)

HUMAN_REVIEW is not triggered by risk_score range (too broad — catches all agent calls).
It fires via intent mismatch detection, plumbed through the Lobster Trap pipeline:

1. **Go layer** (`lobstertrap/internal/inspector/inspector.go`): `PromptMetadata` has two new
   fields: `DeclaredIntent string` and `HasMismatch bool`.
2. **Pipeline** (`lobstertrap/internal/pipeline/pipeline.go`): Before table evaluation,
   `ProcessIngress` sets `meta.DeclaredIntent = declared.DeclaredIntent` and
   `meta.HasMismatch = (declared.DeclaredIntent != "" && declared.DeclaredIntent != meta.IntentCategory)`.
3. **Policy table** (`lobstertrap/internal/policy/table.go`): `getFieldValue` maps
   `"declared_intent"` and `"has_mismatch"` to the new fields.
4. **Policy rule** (`proxy/policy.yaml`): `human_review_mismatch` fires on
   `declared_intent="summarize"` AND `has_mismatch=true`.
5. **Analysis agent** (`agents/analysis.py`): declares `declared_intent="summarize"`,
   DPI detects `"data_access"` → mismatch → HUMAN_REVIEW.

After full demo run (14 scenarios), result: **exactly 3 HUMAN_REVIEW entries** (one per
non-blocked pipeline: admin + analyst + GDPR), all from `analysis-agent-v1`.

**CRITICAL:** If you change a Go file in lobstertrap, `make build` is required.
`make start` does NOT restart running containers — use `docker compose down && make start`.

## Confirmed Behaviour

- [x] `GET /review/queue` returns `[]` when audit log has no `HUMAN_REVIEW` entries
- [x] `GET /review/queue` returns pending items (decision=None) correctly
- [x] `GET /review/queue?status=all` includes both pending and decided items
- [x] `GET /review/queue?status=approved` filters correctly after a decision
- [x] `POST /review/{id}/decide` appends to `review_decisions.jsonl`, returns `ReviewItem`
- [x] `POST /review/{id}/decide` returns 404 for unknown `request_id`
- [x] `POST /review/{id}/decide` returns 409 on re-decision (idempotent guard)
- [x] After full demo run: `GET /review/queue` returns exactly 3 pending items (analysis-agent-v1)
- [x] Dashboard "Pending Review" counter shows 3 (down from 16 before fixes)

## Bugs Found / Fixed

- **16 false HUMAN_REVIEW entries per demo run:** Root causes were (a) policy range
  `0.2-0.5` catching all agent calls, and (b) `block_harm_violence` and
  `block_obfuscation_evasion` not blocking their scenarios (those ran through pipeline
  generating extra HUMAN_REVIEW entries). Fixed by switching to `has_mismatch` trigger
  and fixing the detection patterns.

## What's Next After Human-Review

Per scaffold-tasks.md priority order:
- Full adversarial test coverage (10+ attack vectors) — COMPLETE
