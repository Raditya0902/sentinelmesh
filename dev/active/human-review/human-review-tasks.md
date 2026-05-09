# Tasks: Human-Review Queue

## Checklist

### Phase 1 — Schemas

- [x] Add `ReviewDecision` model: `decision: Literal["approve","reject"]`, `note: str = ""`
- [x] Add `ReviewItem` model: `request_id`, `timestamp`, `agent_id`, `risk_score`, `rule_name`, `raw`, `decision | None`, `note`
- [x] Add `REVIEW_DECISIONS_PATH` constant (sibling of `AUDIT_LOG_PATH`, same `logs/` dir)

### Phase 2 — `GET /review/queue`

- [x] `_read_audit_human_review()` — scans audit log, filters `action == "HUMAN_REVIEW"`
- [x] `_read_decisions()` — reads `review_decisions.jsonl`, returns `{request_id → {decision, note}}`
- [x] `_to_review_item()` — joins audit entry + decision into `ReviewItem`
- [x] `GET /review/queue?status=pending|approved|rejected|all` (default: pending)

### Phase 3 — `POST /review/{request_id}/decide`

- [x] 404 if `request_id` not in audit log HUMAN_REVIEW entries
- [x] 409 if already decided
- [x] Appends `{request_id, decision, note, decided_at}` to `review_decisions.jsonl`
- [x] Returns completed `ReviewItem`

### Verification (all via TestClient + synthetic audit log)

- [x] Empty log → `GET /review/queue` returns `[]`
- [x] One HUMAN_REVIEW entry, no decision → appears as pending
- [x] `status=all` includes pending items
- [x] `POST /decide approve` → 200, decision=approve, note preserved
- [x] After approve, pending queue empty
- [x] `status=approved` returns the approved item
- [x] Re-decide → 409
- [x] Unknown id → 404
- [x] `human-review-context.md` confirmed behaviours updated
- [x] `scaffold-tasks.md` marked `[x]`

### Phase 4 — HUMAN_REVIEW false-positive fix (post-completion)
- [x] Diagnose 16 false positives: risk_score range too broad + harm/obfuscation patterns not blocking
- [x] Add `DeclaredIntent string` + `HasMismatch bool` to `PromptMetadata` (inspector.go)
- [x] Enrich metadata with declared headers before table eval (pipeline.go)
- [x] Add `declared_intent` + `has_mismatch` to `getFieldValue` (table.go)
- [x] Change policy rule to: `declared_intent="summarize"` AND `has_mismatch=true`
- [x] Change `agents/analysis.py` declared_intent to `"summarize"`
- [x] Align `agents/critic.py` → `"general"`, `agents/action.py` → `"code_execution"` to avoid unintended mismatches
- [x] `make build` to rebuild lobstertrap, full restart with `docker compose down && make start`
- [x] Verified: 3 HUMAN_REVIEW entries after demo (all from analysis-agent-v1)

## Status: COMPLETE ✅
