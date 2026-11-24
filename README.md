# SentinelMesh

[![CI](https://github.com/Raditya0902/sentinelmesh/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Raditya0902/sentinelmesh/actions/workflows/ci.yml)

> **Policy-enforced multi-agent orchestration with real-time threat visibility**

SentinelMesh is a governance layer for a LangGraph multi-agent pipeline. Every LLM call, both prompt and response, passes through **Lobster Trap**, a Go Deep Prompt Inspection proxy, before it reaches the model. Callers are bound to roles by API key. Agents are bound to identities and allowed intents by per-agent keys. Flagged requests pause the run until a human approves or rejects them. Every decision lands in an audit log that the API only appends to and archives, never deletes.

It started as a hackathon entry (*Transforming Enterprise Through AI*, Track 1: Agent Security & AI Governance) and was then hardened in three more passes. The full history is in [docs/CHANGELOG.md](docs/CHANGELOG.md).

**Contents:** [What I built](#what-i-built) · [Built on Lobster Trap](#built-on-lobster-trap-sponsor) · [Architecture](#architecture) · [Security model](#security-model) · [Benchmarks](#benchmarks) · [Quick start](#quick-start)

---

## What I built

- **LangGraph multi-agent orchestrator** ([`orchestrator/`](orchestrator/), [`agents/`](agents/)). Extraction, analysis, critic and action agents in a `StateGraph`, with an RBAC preflight and one shared LLM-step wrapper that detects proxy blocks and review holds.
- **RBAC over ChromaDB namespaces** ([`rbac/`](rbac/)). Four roles. Namespace access is checked in the orchestrator and again in `NamespacedVectorStore` before every query or upsert.
- **FastAPI governance API** ([`api/`](api/), [`audit/`](audit/), [`storage.py`](storage.py)):
  - API key → role binding that fails closed.
  - Per-key token-bucket rate limiting.
  - Audited auth failures and role spoofing.
  - Archive-only audit rotation.
  - **Durable human-in-the-loop**: LangGraph `interrupt()` with a SQLite checkpointer. A held step is replayed once, with a single-use approval bound to the request body.
- **Scoped action tools** ([`agents/action_tools.py`](agents/action_tools.py)). A closed, Pydantic-validated tool set, re-checked against RBAC before it runs.
- **Streamlit governance dashboard** ([`dashboard/`](dashboard/)). Audit table, timeline, attack charts, and the review queue.
- **Attack suite** ([`tests/run_attacks.py`](tests/run_attacks.py), [`trigger_demo.py`](trigger_demo.py)). 18 in-container checks and 16 live scenarios, plus 158 pytest tests behind an 80% coverage gate.
- **Policy pack** ([`proxy/policy.yaml`](proxy/policy.yaml)). Ingress/egress rules, the agent registry, and network and filesystem policy, tuned against false positives on the happy path.
- **CI** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). gofmt, Go tests, policy tests, pytest with coverage, and the attack suite against a proxy + API + ChromaDB stack (LLM-dependent checks skipped, since CI has no LLM backend).

## Built on Lobster Trap (sponsor)

The DPI proxy in [`lobstertrap/`](lobstertrap/) is **[Lobster Trap](https://github.com/veeainc/lobstertrap)**, provided by the hackathon sponsor under the [MIT license](lobstertrap/LICENSE). I didn't write it. Lobster Trap supplies the reverse proxy, the regex DPI engine, the match-action policy table, the audit log and its built-in dashboard.

My changes to it (details in [docs/CHANGELOG.md](docs/CHANGELOG.md)):

- **Agent identity and intent binding.** Per-agent keys (`X-Agent-Key`) and an `agents:` registry in policy. Spoofed intents, unknown agents and bad keys are denied, and unknown agents and bad keys look the same. Keys are stripped before forwarding. ([`identity.go`](lobstertrap/internal/pipeline/identity.go))
- **Human-review approval ledger.** A held request is released once, only for the same agent, intent and byte-identical body, after a first-decision-wins approval made within 15 minutes. ([`review.go`](lobstertrap/internal/pipeline/review.go))
- **Strict policy loading.** Unknown keys, fields and match types, invalid regexes, unimplemented actions and bad values are load errors instead of silent ALLOW/no-op. ([`loader.go`](lobstertrap/internal/policy/loader.go))
- **Auth-failure lockout.** After 10 failed agent authentications a minute, the (peer IP, agent) pair is locked out. ([`authlimit.go`](lobstertrap/internal/pipeline/authlimit.go))
- **Concurrent DPI scan.** Pattern sets run in parallel, so 4 KB p50 dropped from 12.4 ms to 3.0 ms. The server also gained read/write/idle timeouts.
- **Egress bypass fixes:**
  - gzip responses skipped egress DPI. Now `Accept-Encoding` is stripped, and an encoded or unparseable body is denied as `egress_uninspectable`.
  - Only `choices[0]` was scanned. Now every choice is.
- **Ollama bypass fixes.** `/api/generate` prompts and `/api/chat` replies were invisible to DPI, and Ollama's implicit streaming slipped through.
- **Network and filesystem enforcement.** These policy sections were parsed but never enforced. They now are, with `**`-aware globs.
- **Classifier tuning.** Generic words no longer drive intent classification, the exfiltration patterns are narrower, and tie-breaking is deterministic instead of following Go map order.
- **Proxy correctness:**
  - The backend path prefix was dropped.
  - The `_lobstertrap` field was forwarded to the backend.
  - The trailing-slash endpoint check could be bypassed.
  - Malformed JSON was forwarded uninspected.
  - Request bodies had no size limit.
  - Streaming denials weren't audited.
  - Request IDs now carry a per-boot nonce, so they never repeat.
  - Dashboard stats now dedupe by request.

---

## Architecture

The full diagram and component notes are in **[docs/architecture.md](docs/architecture.md)**.

```
caller ──X-Sentinel-Key──▶ FastAPI ──▶ Orchestrator (RBAC preflight)
                                          │
                     Extraction ─▶ Analysis ─▶ Critic ─▶ Action (write roles only)
                          │  every LLM call, with X-Agent-Key
                          ▼
            ┌─────────────────────────────────────────────┐
            │ Lobster Trap: identity → ingress DPI → rules │
            │   → network/filesystem → LLM → egress DPI    │
            └─────────────────────────────────────────────┘
                          │                        │
              HUMAN_REVIEW → interrupt()      audit.jsonl ─▶ dashboards
              (SQLite checkpoint, admin decides, one-time replay)
```

## Security model

**[docs/threat-model.md](docs/threat-model.md)** lists every in-scope threat with its control, where it lives, and the test that verifies it. It also lists what is *not* defended.

The main limit: DPI is regex-based. It catches known attack phrasings, not paraphrased, multilingual or semantic ones. The other controls don't depend on DPI:

- Key-bound roles and agent identities.
- RBAC on every vector-store call.
- A closed action tool set.
- Body-bound review approvals.

Three example attack walkthroughs (injection, PII egress, RBAC) are in [docs/attack-scenarios.md](docs/attack-scenarios.md); the full list is the [demo table](#demo-16-live-scenarios).

---

## How Lobster Trap enforces policy

- **Deep Prompt Inspection.** Regex metadata extraction from every prompt and response, with no LLM call for classification.
- **Match-action rules.** YAML rules match on extracted fields (`risk_score`, `intent_category`, `has_mismatch`, …) and pick an action.
- **Three-layer ingress enforcement**, in order:
  1. The priority-ordered `ingress_rules`.
  2. Network policy (`denied_domains` / `allowed_domains`).
  3. Filesystem policy (`denied_paths`, `**`-aware).
- **Egress filtering.** Output is buffered and inspected before delivery. Streaming is denied, and an undecodable response is denied rather than forwarded.
- **Agent identity binding.** See above. The proxy refuses to start if a registered agent has no key. Non-chat endpoints aren't inspected, so only `GET`/`HEAD` pass through.

### Active Policy Rules

| Rule | Trigger | Action |
|------|---------|--------|
| `block_prompt_injection` | Injection patterns detected | DENY |
| `block_harm_violence` | Weapons / harm requests | DENY |
| `block_malware_request` | Malware / exploit generation | DENY |
| `block_data_exfiltration` | Exfiltration patterns | DENY |
| `block_obfuscation_evasion` | Base64 payloads, char-splitting | DENY |
| `block_sensitive_paths` | `/etc/passwd`, `.ssh/`, etc. | DENY |
| `block_dangerous_commands` | High-risk system commands (`risk_score ≥ 0.3`) | DENY |
| `block_pii_request` | SSN / credential requests | DENY |
| `block_credential_leak` | Credentials in model output | DENY (egress) |
| `block_pii_exfiltration` | PII in model output | DENY (egress) |
| `quarantine_high_risk` | `risk_score > 0.8` | QUARANTINE |
| `human_review_mismatch` | `summarize`-declared requests where DPI detects a non-general intent | HUMAN_REVIEW |
| `allow_all_agent_actions` | Every agent call that cleared all security rules | ALLOW |

### Intent Mismatch Detection

Each agent declares its intent in the request header (`_lobstertrap.declared_intent`). The declaration is authenticated (see identity binding above), so a caller can't pick an intent to dodge a rule. Lobster Trap independently classifies the actual intent via DPI. When the analysis agent declares `summarize` but DPI detects a non-general intent (e.g. `data_access`, `network`, `credential_access`), the request is flagged for human review. A mismatch that resolves to `general` is treated as low-risk ambiguity and allowed:

| Agent | Declared | DPI Detects | Result |
|-------|----------|-------------|--------|
| extraction | `data_access` | `data_access` | ALLOW |
| **analysis** | **`summarize`** | **`data_access`** | **HUMAN_REVIEW** |
| **analysis** | **`summarize`** | **`general`** | **ALLOW** |
| critic | `general` | `general` | ALLOW |
| action | `code_execution` | `code_execution` | ALLOW |

---

## Human-in-the-Loop

A `HUMAN_REVIEW` verdict actually gates the run:

1. The proxy holds the call. The agent step records the review, and the LangGraph run pauses (`interrupt()`, checkpointed by `thread_id`). `POST /run` returns `status: "pending_review"`, `review_request_id`, and `thread_id`.
2. An admin approves or rejects with `POST /review/{request_id}/decide` (or from the dashboard). The decision is written to `review_decisions.jsonl` first, then the run resumes.
3. **Approve** replays the held step with `X-Sentinel-Review-Approved: <request_id>`. The proxy releases it only if the first decision on that ID is an approval made after the hold and less than 15 minutes ago, the agent, intent and forwarded body are byte-identical, and the approval hasn't been used. The audit row shows `human_review_approved` / `review_approval: accepted:<id>`. **Reject** ends the run as blocked.

Paused runs are checkpointed to SQLite (`SENTINEL_CHECKPOINT_DB`, on the `api_data` volume) for up to 24 h, so they survive an API restart. Run a single uvicorn worker (the per-key rate limiter is per process). Audit rotation is refused while any run is paused. If the checkpoint is gone (the `api_data` volume was deleted, or the run expired), a later decision is still recorded, with `resumed: false`.

## Action Agent Tools

The action agent (write roles only) proposes exactly one JSON tool call, which is validated with Pydantic before anything executes:

| Tool | Effect | Constraints |
|---|---|---|
| `write_finding(namespace, text)` | Upserts into ChromaDB through `NamespacedVectorStore` | `namespace` must be `findings`; caller's role re-checked |
| `notify(channel, message)` | Appends to `logs/notifications.jsonl` (mock notifier) | lowercase channel, ≤1000 chars |

Unknown tools, extra fields, and other namespaces are rejected and audited as `action_tool_denied`. Executed calls are audited as `action_tool_executed`.

## RBAC — Two Enforcement Layers

Role-based access control is enforced independently at two layers. Either one can block a request:

```
1. Orchestrator node     — validates role + namespace before any LLM call
2. NamespacedVectorStore — RBAC check before every ChromaDB query or upsert
```

The proxy doesn't see caller roles. It enforces agent identity and intent (above).

**Roles and namespace access:**

| Role | Namespaces | Write |
|------|-----------|-------|
| `admin` | all (incl. `findings`) | yes |
| `analyst` | general, legal | no |
| `auditor` | audit | no |
| `readonly` | general | no |

---

## Governance Dashboard

The Streamlit dashboard provides a real-time single pane of glass:

- **Color-coded audit table** — DENY (red), HUMAN_REVIEW (blue), ALLOW/LOG (green)
- **Event timeline** — scatter plot of every agent action over time
- **Attack frequency chart** — bar chart of events by agent + action type
- **Human review queue** — approve (resumes the paused run) or reject flagged requests; decisions persisted to `review_decisions.jsonl`

---

## Demo: 16 Live Scenarios

```bash
python trigger_demo.py
```

Fires 16 scenarios against the live stack. The HUMAN_REVIEW scenario stays paused; approve it in the dashboard to resume it.

| # | Scenario | Expected |
|---|----------|----------|
| 1 | Full admin pipeline | ALLOW |
| 2 | Read-only analyst query | ALLOW |
| 3 | GDPR compliance query (intent mismatch) | HUMAN_REVIEW |
| 4 | Prompt injection — ignore previous instructions | DENY |
| 5 | PII request — SSN lookup | DENY |
| 6 | Malware — keylogger generation | DENY |
| 7 | Data exfiltration — POST to evil.com | DENY |
| 8 | Sensitive path — /etc/passwd + .ssh/id_rsa | DENY |
| 9 | Harm — pipe bomb instructions | DENY |
| 10 | Obfuscation — base64-encoded injection | DENY |
| 11 | RBAC — analyst → hr namespace | DENY |
| 12 | RBAC — readonly → finance namespace | DENY |
| 13 | RBAC — auditor → legal namespace | DENY |
| 14 | Auth — unknown API key | 401 |
| 15 | Spoof — analyst key sends `"role": "admin"` | 422 (audited) |
| 16 | Spoof — critic agent's real key declares `data_access`, straight to the proxy | DENY |

The in-container suite (`make demo`, `tests/run_attacks.py`) runs 18 checks. It adds a forged agent key and a full HUMAN_REVIEW → approve → resume round trip.

> The analysis step is occasionally held for review on benign input. DPI intent classification is a keyword heuristic, and LLM-generated extraction text sometimes trips it. That's a false positive an admin can release, not a bypass.

---

## Benchmarks

`BenchmarkProcessIngress` ([`bench_test.go`](lobstertrap/internal/pipeline/bench_test.go)) times the full ingress path with the live policy: DPI, identity check, rule table and audit encoding. Apple M4, 2000 iterations per case:

| Prompt | p50 | p99 |
|---|---|---|
| Injection attempt (65 B) | 0.08 ms | 0.11 ms |
| PII-bearing task (89 B) | 0.10 ms | 0.13 ms |
| Short benign task (128 B) | 0.15 ms | 0.52 ms |
| Task + 1 KB document | 0.77 ms | 0.96 ms |
| Task + 4 KB document | 3.0 ms | 4.1 ms |

Before the concurrent scan, the 4 KB case was 12.4 ms p50. These are wall-clock numbers on a 10-core machine. CPU per request is about 4x higher and linear in prompt length (see [threat-model.md](docs/threat-model.md#performance-cost-of-inspection)).

```bash
cd lobstertrap && go test ./internal/pipeline/ -run '^$' -bench BenchmarkProcessIngress -benchtime=2000x
```

## Tests

```bash
make test     # policy test (11 cases) + pytest (158 tests, 80% coverage gate)
make test-go  # go test ./... in lobstertrap/
make demo     # 18-check attack suite inside Docker (live LLM)
```

---

## Quick Start

Runs locally with Docker Compose (four containers: proxy, API, dashboard, ChromaDB).

**Prerequisites:** [Docker](https://docs.docker.com/get-docker/) with Docker Compose, plus a [Groq API key](https://console.groq.com/keys) (the default backend, `openai/gpt-oss-120b`). To run fully local instead, set `LLM_BACKEND_URL=http://host.docker.internal:11434` and `LLM_MODEL=llama3:latest` and run [Ollama](https://ollama.com/).

```bash
# 1. Clone
git clone https://github.com/Raditya0902/sentinelmesh.git
cd sentinelmesh

# 2. Configure environment + generate one API key per role
cp .env.example .env   # set GROQ_API_KEY
make keys   # paste the printed SENTINEL_CALLER_KEYS and LT_AGENT_KEYS lines into .env

# 3. Build + start (Go binary compiled inside Docker)
make build
make start

# 4. Seed ChromaDB with sample documents
make seed

# 5. Open the dashboard
open http://localhost:8501

# 6. Run the attack demo
python trigger_demo.py
```

### Ports (local Docker)

| Service | Port |
|---------|------|
| Governance Dashboard | 8501 |
| FastAPI backend | 8000 |
| Lobster Trap proxy | 8080 |
| ChromaDB | 8001 |

### API Endpoints

```
GET    /health                      — liveness check                     (public)
POST   /run                         — run the pipeline as the key's role (any key)
GET    /audit?limit=50              — tail the audit log                 (admin, auditor)
POST   /audit/rotate                — archive audit + decisions logs     (admin)
GET    /review/queue?status=pending — list HUMAN_REVIEW items            (admin, auditor)
POST   /review/{request_id}/decide  — approve/reject; resumes the paused run (admin)
```

### Authentication

- Every call except `/health` needs an `X-Sentinel-Key` header. The server maps each key to a role through `SENTINEL_CALLER_KEYS` (a JSON object of key → role). Callers never choose their own role, and a `role` field in the body is rejected with 422.
- `SENTINEL_API_KEY` is still accepted as a single **admin** key. The dashboard uses it.
- **Fails closed.** The API won't start without keys. `SENTINEL_DEMO_MODE=1` allows a keyless local demo: anonymous calls run as `readonly` and governance endpoints are open. Never set it in a deployment.
- **Audited.** Every 401 or 403, and every body that tries to set `role`, is written to the audit log (`auth_missing_key`, `auth_invalid_key`, `auth_role_denied`, `auth_role_spoof_attempt`). The presented key is never logged.
- **History isn't deleted.** `POST /audit/rotate` copies `audit.jsonl` to `audit-<timestamp>.jsonl` and truncates the original in place (the proxy holds it open with `O_APPEND`). Rotate when idle: a proxy write that lands between the copy and the truncate is lost.

---

## Project Structure

```
sentinelmesh/
├── agents/                 # LangGraph agents
│   ├── base.py             # LobsterTrapClient: single LLM call entry point
│   ├── extraction.py       # Reads documents from ChromaDB
│   ├── analysis.py         # Summarizes and classifies
│   ├── critic.py           # Reviews output for compliance
│   ├── action.py           # One validated tool call per run (write roles)
│   └── action_tools.py     # write_finding / notify + Pydantic validation
├── orchestrator/main.py    # StateGraph, RBAC preflight, human-review interrupt
├── api/                    # FastAPI: app factory, auth, rate limit, review
├── audit/writer.py         # flock'd audit appends, archive-only rotation
├── storage.py              # SQLite for paused runs + review→thread map
├── config.py               # Typed settings (pydantic-settings)
├── rbac/                   # Roles, NamespacedVectorStore, seed data
├── proxy/policy.yaml       # Active Lobster Trap policy
├── dashboard/app.py        # Streamlit governance dashboard
├── lobstertrap/            # Lobster Trap (sponsor code, modified; see above)
├── tests/                  # pytest suite + run_attacks.py / attack_identity.py
├── docs/                   # architecture, threat model, attack scenarios, changelog
├── trigger_demo.py         # 16 live scenarios against the running stack
├── docker-compose.yml      # 4-container stack
└── Makefile                # build / start / seed / keys / test / demo
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent orchestration | LangGraph, LangChain |
| DPI proxy | [Lobster Trap](https://github.com/veeainc/lobstertrap) (Go, sponsor-provided, modified) |
| LLM backend | Groq (`openai/gpt-oss-120b`) or Ollama (`llama3:latest`) |
| Vector store | ChromaDB with RBAC namespaces |
| API | FastAPI, Pydantic, SQLite (LangGraph checkpoints) |
| Dashboard | Streamlit, Plotly |
| Infrastructure | Docker, Docker Compose |
| CI | GitHub Actions |

## Credits

- **Lobster Trap** by the hackathon sponsor: [github.com/veeainc/lobstertrap](https://github.com/veeainc/lobstertrap), MIT-licensed ([lobstertrap/LICENSE](lobstertrap/LICENSE)). Modifications are listed [above](#built-on-lobster-trap-sponsor).
- Hackathon submission materials are in [SUBMISSION.md](SUBMISSION.md).
