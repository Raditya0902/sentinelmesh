# Context: Project Scaffold

## Key Decisions

### Every LLM call routes through Lobster Trap — no exceptions
`agents/base.py` creates an OpenAI client with `base_url=LOBSTER_TRAP_URL/v1`.
All agents import `call_llm` from base — there is no other path to the model.
Each call attaches `_lobstertrap: {agent_id, declared_intent}` so the proxy knows
who is calling and what they said they would do (mismatch = HUMAN_REVIEW trigger).

### Lobster Trap Dockerization (Native Build)
To resolve "exec format error" in Docker, Lobster Trap is built using a multi-stage
Dockerfile (`lobstertrap/Dockerfile`) that compiles the Go source into a native
Linux binary during the `docker compose build` phase.

### Dashboard Type Safety
Fixed `TypeError: '<' not supported between instances of 'float' and 'str'` in the 
Streamlit dashboard by casting all unique IDs (agent_id, action, rule_name) to 
strings and dropping NaNs before sorting the filter lists.

### Backend Routing for Containers
Lobster Trap in Docker is configured with `--backend http://host.docker.internal:11434`
to ensure it can reach the Ollama service running on the host machine. 
`host.docker.internal` is mapped via `extra_hosts` in `docker-compose.yml`.

### Action Agent declared_intent Fix
`agents/action.py` previously passed `declared_intent="general"` to `call_llm`.
Changed to `declared_intent="write_action"` so every action-agent audit entry carries
a meaningful intent label. Affects dashboard readability and Lobster Trap's mismatch
detection accuracy for write operations.

### Audit Log Persistence
The `logs/` directory is mounted as a volume across `lobstertrap`, `api`, and 
`dashboard` containers to ensure real-time log sharing and persistence.

### CI/CD (GitHub Actions) Implementation
A unified CI workflow (`.github/workflows/ci.yml`) is active. It performs:
1. **Go Testing**: Runs internal unit tests for Lobster Trap.
2. **Policy Verification**: Builds the binary and runs `lobstertrap test` against the custom `proxy/policy.yaml`. Benign prompts are correctly verified against the `log_all_agent_actions` rule (treating LOG as ALLOW for test assertions).
3. **Python Testing**: Runs `pytest` for RBAC (`tests/test_rbac.py`) and Pipeline integration (`tests/test_pipeline.py`).

### Stale Decision Bug Fix (api/main.py)
Lobster Trap resets its request counter on restart, reusing `req-1`, `req-2`, `req-3`.
Old decisions in `logs/review_decisions.jsonl` silently matched the new entries → queue showed empty, approve/reject returned 409.

Fix applied in two places:
- `_to_review_item()`: if `entry.timestamp > decision.decided_at`, decision is stale → treat entry as pending (`decision=None`)
- `decide_review_item()`: same staleness check before the 409 guard — stale decisions are overwritten, not blocked

This makes the queue self-healing across Lobster Trap restarts. No need to clear `review_decisions.jsonl` manually.

### trigger_demo.py Expanded (6 → 14 scenarios)
Now covers every rule type visible in the dashboard (14 total):
- 2 ALLOW (admin full pipeline, analyst read-only)
- 1 HUMAN_REVIEW scenario (GDPR compliance query, analyst/legal) — all 3 non-blocked pipelines generate HUMAN_REVIEW queue entries via analysis-agent-v1
- 7 Lobster Trap DENY: `block_prompt_injection`, `block_pii_request`, `block_malware_request`, `block_data_exfiltration`, `block_sensitive_paths`, `block_harm_violence`, `block_obfuscation_evasion`
- 4 RBAC DENY: analyst→hr, readonly→finance, auditor→legal, invalid role `hacker`

Output now shows emoji indicators (🟢/🔴) and rule-level error message per scenario.

### Dashboard Visual Fixes (session 2026-05-09)
Three bugs found and fixed in `dashboard/app.py`:
- **Color coding**: `color_action()` was defined but never applied. Fixed with `Styler.map()` on the action column using `ACTION_BG` dict (dark red for DENY, dark blue for HUMAN_REVIEW, dark green for ALLOW).
- **Risk heatmap blank**: `px.density_heatmap` with <10 data points and DENY entries reporting `risk_score: 0.0` rendered invisible bars. Replaced with `px.bar` showing **event count** (not avg risk) grouped by agent + action.
- **Timeline flat lines**: `pd.Grouper(freq='1min')` grouped all events (which fire within seconds) into one bucket → single point per series, no line possible. Replaced with `px.scatter` — each event is a colored dot on agent×time axes.
- **Unused imports**: Removed `Counter`, `datetime`, `timedelta` from imports.

## Confirmed Behaviour (from final demo run)
...
The following scenarios were verified against the live Docker stack:
- **Normal Flow**: Extraction + Analysis + Critic approval works.
- **Prompt Injection**: Lobster Trap returns `[SENTINEL] Blocked: prompt injection detected.`
- **RBAC Namespace Violation**: Orchestrator blocks before LLM call with `Role X cannot access namespace Y`.
- **PII Ingress/Egress**: Lobster Trap blocks SSN patterns with `[SENTINEL] Blocked: PII request detected.`

## Key File Paths

| File | Purpose |
|------|---------|
| lobstertrap/Dockerfile | Compiles the Go proxy for Linux containers |
| docker-compose.yml | Orchestrates 4 services (chromadb, lobstertrap, api, dashboard) |
| Makefile | High-level targets (start, seed, demo, test) |
| dashboard/app.py | Full governance dashboard (Plotly + Streamlit) |
| README.md | Core project documentation and ASCII architecture |
| SUBMISSION.md | Hackathon submission fields |
| railway.toml | Railway deployment configuration |

## Environment (Final Docker State)

```
Network:          sentinelmesh_default
Ports:            8501 (UI), 8000 (API), 8080 (Proxy), 8001 (Chroma)
Volumes:          ./logs -> /app/logs, ./data -> /app/data
External Dependency: Ollama (host:11434)
```

## Session 2026-05-09 — Final Confirmed State

Everything is working. Live demo verified end-to-end in Docker.

**What was confirmed working:**
- `make build && make start && make seed` → all 4 containers up, ChromaDB seeded
- `python trigger_demo.py` → 14 scenarios: 2 allow + 1 human_review + 7 lobster trap DENY (injection/pii/malware/exfil/paths/harm/obfuscation), 4 RBAC DENY (analyst→hr, readonly→finance, auditor→legal, invalid role)
- All 3 non-blocked pipelines (admin, analyst, GDPR) run the analysis agent → 3 HUMAN_REVIEW queue entries, all from `analysis-agent-v1`
- `GET /review/queue?status=pending` → returns 3 items (all `analysis-agent-v1`)
- `POST /review/{id}/decide` → approve/reject works, idempotent (409 on re-decide)
- Dashboard: color-coded action column, scatter timeline, count bar chart, human review UI

**HUMAN_REVIEW mechanism (final state — intent mismatch, not risk_score range):**
- analysis agent declares `declared_intent="summarize"`, DPI detects `intent_category="data_access"` → `has_mismatch=true`
- Policy rule `human_review_mismatch` fires on `declared_intent="summarize"` AND `has_mismatch=true`
- Go pipeline: `PromptMetadata` has `DeclaredIntent` + `HasMismatch` fields; `pipeline.go` computes mismatch before table eval; `table.go` exposes both as policy-matchable fields
- All 4 agents have aligned declared_intent to avoid unintended triggers (see CLAUDE.md agent table)

**Makefile change made this session:**
- `seed`, `test`, `demo` targets now run inside Docker (`docker compose exec api ...`)
- Reason: host `(base)` conda Python has different ChromaDB version than container → Rust panic on shared `./data/chromadb` volume

**What's next (human tasks, not code):**
- Railway deploy → live URL
- Loom demo video (3-5 min)
- 6-slide PDF
- Cover image (1200×630px)

## Bug Audit Session (2026-05-09)

Full codebase audit was run. Bugs found and fixed:

| # | File | Bug | Fix |
|---|------|-----|-----|
| 1 | `requirements.txt` | `pytest` missing — CI would fail | Added `pytest>=7.0.0` |
| 2 | `.env.example` | `LLM_MODEL=llama3.2` (not pulled) | Changed to `llama3:latest` |
| 3 | `trigger_demo.py` | `s.pop("label")` mutated SCENARIOS in-place | Non-mutating `payload` dict copy |
| 4 | `api/main.py` lines 157, 217 | Timestamp `>` compared strings lexicographically — `Z` vs `+00:00` suffix would compare wrong | Added `_parse_ts()` using `datetime.fromisoformat` |
| 5 | `agents/base.py:34` | `response.choices[0]` with no bounds check — crashes on empty choices | Guarded with `if response.choices else ""` |
| 6 | `trigger_demo.py` | Hardcoded `URL = "http://localhost:8000/run"` | Now reads `API_URL` env var with localhost fallback |
| 7 | `Dockerfile` | `COPY GEMINI.md CLAUDE.md .env.example ./` — AI instruction docs baked into image | Removed GEMINI.md and CLAUDE.md from COPY |

Bugs intentionally NOT fixed (design decisions, not mistakes):
- **HTTP 200 on DENY**: OpenAI SDK throws on 4xx — block message must ride in response body. `_sentinel_blocked()` matches on it. Changing would break Python agent detection.
- **Egress overwrites ingress block info**: Unreachable in practice — `ProcessEgress` is never called when ingress already blocked the request (proxy returns early).
- **Streaming egress bypass**: Agents don't use streaming; fixing requires SSE buffering.

## Start-up Order (Docker)

```bash
make build   # Builds native Go binary + Python environment
make start   # Starts the stack in background
make seed    # Populates ChromaDB namespaces
make demo    # (Optional) Runs local attack suite or use manual curl
```
