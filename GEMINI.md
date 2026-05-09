# SentinelMesh — GEMINI.md
> Context file for Gemini CLI usage on the SentinelMesh hackathon project.
> Read CLAUDE.md first for full project context.

---

## Your Role (Gemini CLI)

You are the secondary AI assistant on this project. Claude Code handles complex
architecture and core logic. You handle speed tasks: UI, boilerplate, docs, configs.

**Do not rewrite or restructure code that Claude Code has already written.**
**Always read existing files before adding to them.**

---

## Task Assignment: Gemini CLI Owns These

### Dashboard (Streamlit)
- `dashboard/app.py` — full Streamlit governance dashboard
- Real-time audit log table (auto-refresh every 3s)
- Blocked attacks counter with red/green indicators
- Risk score heatmap by agent
- Role activity timeline
- Filter by: time range, agent, action type (ALLOW/DENY/QUARANTINE)

### Boilerplate & Config
- `docker-compose.yml` — orchestrates: lobstertrap, fastapi, streamlit, chromadb
- `.env.example` — all required environment variables with descriptions
- `requirements.txt` — pinned dependencies
- `Makefile` — shortcuts: `make start`, `make test`, `make demo`, `make build`

### Documentation
- `README.md` — full project README with architecture diagram (ASCII), setup, demo
- `docs/architecture.md` — detailed architecture writeup for submission
- `docs/attack-scenarios.md` — documents the 3 demo attack scenarios with expected outputs
- `SUBMISSION.md` — filled submission fields (title, short desc, long desc, tags)

### Tests (non-security)
- `tests/test_rbac.py` — unit tests for role enforcement
- `tests/test_pipeline.py` — integration tests for agent pipeline flow

### Deployment
- `railway.toml` or `render.yaml` — deployment config for live demo URL
- `Dockerfile` — multi-stage build for the FastAPI + Streamlit app

---

## Task Assignment: Claude Code Owns These (Do Not Touch)

- `orchestrator/main.py` — LangGraph pipeline
- `agents/*.py` — agent definitions
- `rbac/roles.py` — RBAC enforcement logic
- `proxy/policy.yaml` — Lobster Trap policy rules
- `api/main.py` — FastAPI routes
- `tests/run_attacks.py` — adversarial security tests

---

## Project Stack

```
Language:     Python 3.11+
Agents:       LangGraph (langgraph), LangChain (langchain)
Proxy:        Lobster Trap (Go binary at ./lobstertrap)
Vector DB:    ChromaDB
API:          FastAPI + uvicorn
Dashboard:    Streamlit
Auth:         JWT (python-jose)
Cache:        Redis (optional)
Deploy:       Docker + Railway/Render
```

---

## Key Context

**What Lobster Trap does:**
- Sits as a proxy between LangGraph agents and the LLM (OpenAI-compatible API)
- Every prompt/response passes through it
- Returns structured JSON: `risk_score`, `contains_injection_patterns`,
  `contains_pii`, `contains_credentials`, `contains_exfiltration`
- Policy YAML defines ALLOW/DENY/LOG/QUARANTINE rules

**What the dashboard shows:**
- Real-time feed of all agent calls: timestamp, agent, action, risk score
- Blocked attacks highlighted in red
- Audit trail exportable as CSV (a "regulator could read this")
- Summary stats: total calls, blocked %, avg risk score

**Demo flow for video:**
1. Normal document processing → all green → audit log shows ALLOW
2. Prompt injection attack → DENY → dashboard lights up red
3. PII exfiltration attempt → DENY → output blocked
4. Cross-role access → RBAC DENY → role mismatch alert

---

## Streamlit Dashboard Spec

```python
# dashboard/app.py structure
# - st.title("SentinelMesh — Enterprise AI Governance Dashboard")
# - Top row: 4 metric cards (Total Calls, Blocked, Quarantined, Avg Risk Score)
# - Middle: Live audit log table (auto-refresh with st.rerun every 3s)
# - Bottom left: Risk score distribution chart (plotly bar)
# - Bottom right: Attack type breakdown (plotly pie)
# - Sidebar: filters (time range, agent, action type)
# - Color coding: ALLOW=green, DENY=red, QUARANTINE=orange, LOG=grey
```

---

## README.md Required Sections

1. **What is SentinelMesh** (2-3 sentences)
2. **The Problem** (agents act without guardrails)
3. **Architecture diagram** (ASCII)
4. **Lobster Trap Integration** (how it works as proxy)
5. **Attack Scenarios** (3 demos with expected output)
6. **Setup & Run** (step-by-step)
7. **Tech Stack**
8. **Submission Info** (hackathon, track, team)

---

## Tone for Docs

- Technical but readable
- Concrete — show actual outputs, not just descriptions
- Enterprise-focused — this solves compliance problems
- Confident — "SentinelMesh catches X, blocks Y, logs Z"
