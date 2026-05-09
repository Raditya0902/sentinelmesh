# Tasks: Project Scaffold

## Checklist

### Code scaffold
- [x] Create agents/ package with base.py, extraction.py, analysis.py, action.py, critic.py
- [x] Create orchestrator/main.py with LangGraph StateGraph and AgentState TypedDict
- [x] Create api/main.py with FastAPI: /health, /run, /audit
- [x] Create rbac/roles.py with 4 roles and namespace enforcement
- [x] Create proxy/policy.yaml (SentinelMesh policy forked from default)
- [x] Create configs/sentinelmesh_policy.yaml (production/HIPAA policy)
- [x] Create dashboard/app.py (Streamlit governance dashboard skeleton)
- [x] Create tests/run_attacks.py (3 adversarial attack scenarios)
- [x] Create requirements.txt
- [x] Create .env.example with all env vars documented
- [x] Update .gitignore (add logs/*.jsonl, data/, venv/)
- [x] Create logs/.gitkeep

### Bug fixes
- [x] Fix CLAUDE.md: `--config` → `--policy`, `./lobstertrap` → `./lobstertrap/lobstertrap`, add `--audit-log`
- [x] Fix agents/base.py: read `LLM_MODEL` and `LOBSTER_TRAP_URL` lazily inside methods (not at module scope)
- [x] Fix orchestrator/main.py: call `load_dotenv()` before importing agents, remove unused `import os`
- [x] Fix agents/action.py: `declared_intent="general"` → `"code_execution"` for accurate audit trail + intent mismatch detection

### Environment setup
- [x] Create .venv (Python 3.13)
- [x] pip install -r requirements.txt (all packages installed successfully)
- [x] Copy .env.example → .env
- [x] Update .env: LLM_MODEL=llama3:latest (llama3.2 not available locally)
- [x] Verify Ollama running with llama3:latest
- [x] Verify Lobster Trap running and proxying to Ollama (/v1/models responded)

### Smoke test
- [x] Run PYTHONPATH=. python orchestrator/main.py — pipeline completed end-to-end
- [x] Lobster Trap blocked SSN ingress via block_pii_request rule — confirmed
- [x] _lobstertrap metadata present on all responses — proxy wiring confirmed
- [x] action_node skipped for analyst role — RBAC routing confirmed
- [x] Critic returned approved=false with GDPR/HIPAA concerns — critic logic confirmed

### Bug audit (2026-05-09)
- [x] Add `pytest>=7.0.0` to requirements.txt (was missing — broke CI)
- [x] Fix `.env.example` LLM_MODEL: `llama3.2` → `llama3:latest`
- [x] Fix `trigger_demo.py`: replace `s.pop("label")` with non-mutating payload copy
- [x] Fix `api/main.py`: timestamp comparison now uses `_parse_ts()` / `datetime.fromisoformat` at both sites (lines 157, 217)
- [x] Fix `agents/base.py:34`: guard `choices[0]` access — returns `""` on empty list
- [x] Fix `trigger_demo.py`: read `API_URL` from env (no longer hardcoded to localhost)
- [x] Fix `Dockerfile`: remove `GEMINI.md CLAUDE.md` from COPY (AI docs not needed in image)

## Status: COMPLETE ✅

## What's NOT done yet (next features — ordered by priority for hackathon)

- [x] **docker-compose** — orchestrates lobstertrap + fastapi + streamlit + chromadb (Gemini task)
- [x] **ChromaDB integration** — namespace enforcement at vector store level (Claude task)
- [x] **Human-review queue** — endpoint in FastAPI + dashboard view (Claude task)
- [x] **Full Streamlit dashboard** — real charts, filters, color coding, CSV export (Gemini task)
- [x] **CI/CD** — GitHub Actions with lobstertrap test + pytest (Gemini task)
- [x] **Demo scripts** — demo/ directory with attack scenario scripts (Gemini task)
- [x] **Architecture diagram + README** — docs/ directory (Gemini task)
- [x] **Full adversarial test coverage** — 14 attack vectors in tests/ (Claude task)
- [x] **Deployment config** — Railway/Render YAML for live demo URL (Gemini task)
