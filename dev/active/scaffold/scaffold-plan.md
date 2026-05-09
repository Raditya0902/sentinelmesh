# Plan: Project Scaffold

## Goal
Stand up the full SentinelMesh directory structure with working skeletons for
every major subsystem so subsequent features can build on a consistent foundation.

## Phases

### Phase 1 — Directory structure ✅
Create all top-level packages: agents/, orchestrator/, proxy/, rbac/, dashboard/, api/, tests/, configs/, logs/

### Phase 2 — RBAC layer ✅
Define the 4 roles (admin, analyst, auditor, readonly) with namespace scoping and write-access guards.

### Phase 3 — Agent base + 4 agents ✅
- base.py: LobsterTrapClient wired to LOBSTER_TRAP_URL/v1 with _lobstertrap metadata headers
- extraction.py, analysis.py, action.py, critic.py: individual agent logic

### Phase 4 — LangGraph orchestrator ✅
StateGraph with 5 nodes: orchestrator → extraction → analysis → critic → (action if write role)
RBAC check happens at orchestrator_node before any LLM call fires.

### Phase 5 — FastAPI backend ✅
GET /health, POST /run (triggers pipeline), GET /audit (tails JSONL log)

### Phase 6 — Proxy policy ✅
proxy/policy.yaml forked from lobstertrap/configs/default_policy.yaml, tuned for SentinelMesh.
quarantine_high_risk (>0.8), human_review_elevated_risk (0.5–0.8), log_all for audit trail.

### Phase 7 — Streamlit dashboard skeleton ✅
Live audit feed, blocked-event expanders, rule breakdown bar chart, risk score histogram.

### Phase 8 — Adversarial test suite ✅
tests/run_attacks.py: 3 canonical attacks (prompt injection, PII exfiltration, cross-role access).
Exit 0 = all blocked. Exit 1 = policy gap detected.

### Phase 9 — Supporting files ✅
requirements.txt, .env.example, .gitignore, configs/sentinelmesh_policy.yaml (production/HIPAA)

### Phase 10 — Environment setup & bug fixes ✅
- Created .venv (Python 3.13), installed requirements.txt
- Copied .env.example → .env, set LLM_MODEL=llama3:latest (llama3.2 not available locally)
- Fixed CLAUDE.md: wrong lobstertrap flag (--config → --policy), wrong binary path
- Fixed agents/base.py: env vars were read at module load time (before load_dotenv ran) → moved to lazy reads inside methods
- Fixed orchestrator/main.py: load_dotenv() was called after agent imports → moved before all agent imports

### Phase 11 — Smoke test passed ✅
Full pipeline ran end-to-end against live Ollama + Lobster Trap:
- Lobster Trap blocked `block_pii_request` on extraction ingress (SSN in document)
- Analysis received the DENY message and surfaced GDPR/HIPAA concerns
- Critic returned approved=false with two concerns
- Action node was correctly skipped (analyst role, can_write=False)
- `_lobstertrap` metadata header visible in all responses — proxy wiring confirmed

### Phase 12 — CI/CD & Policy Cleanup ✅
- Implemented GitHub Actions workflow (`.github/workflows/ci.yml`) for Go and Python testing.
- Cleaned up `proxy/policy.yaml` (removed external domains).
- Fixed `lobstertrap test` tool to handle `LOG` actions correctly in policy verification.

