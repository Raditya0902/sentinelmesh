# SentinelMesh

> **Policy-Enforced Multi-Agent Orchestration with Real-Time Threat Visibility**
> Hackathon: Transforming Enterprise Through AI — Track 1: Agent Security & AI Governance

SentinelMesh is a governance layer for a LangGraph multi-agent pipeline. Every LLM call, both prompt and response, passes through **Lobster Trap**, a Go-based Deep Prompt Inspection proxy, before it reaches the model. Callers are bound to roles by API key. Agents are bound to identities and allowed intents by per-agent keys. Flagged requests pause the run until a human approves or rejects them. Every decision lands in an append-only audit log.

What it does and doesn't defend against is in **[docs/threat-model.md](docs/threat-model.md)**. In short, the DPI is regex-based. It catches known attack phrasings, not paraphrased or multilingual ones.

---

## The Problem: The Control Gap

As enterprises deploy multi-agent AI systems, three critical risks emerge:

| Risk | What Goes Wrong |
|------|----------------|
| **Prompt Injection** | Malicious input hijacks an agent's instructions |
| **PII / Credential Leakage** | Model outputs expose sensitive data in responses |
| **Unauthorized Data Access** | Agents query data outside their role's permission scope |

Traditional API gateways don't understand LLM intent. SentinelMesh does.

---

## How It Works

```
                       User Request
                           │
                           ▼ 
┌──────────────────────────────────────────────────────┐
│              Orchestrator (LangGraph)                │
│         RBAC preflight — validates role + namespace  │
└──────────────────────────┬───────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────┐
│                  Lobster Trap Proxy                  │
│                                                      │
│  Ingress DPI ──► Match-Action Table ──► Decision     │
│   • intent classification    ALLOW                   │
│   • risk scoring             DENY                    │
│   • injection detection      QUARANTINE              │
│   • PII / credential scan    LOG                     │
│   • mismatch detection       HUMAN_REVIEW            │
│                                                      │
│  Egress DPI  ──► Scans model output before delivery  │
└──────────────────────────┬───────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
    Extraction          Analysis          Action
      Agent              Agent             Agent
   (data_access)       (summarize)    (code_execution)
          │                │
          └────────────────┘
                    │
                    ▼
             Critic Agent
           (quality review)
                    │
                    ▼
         ┌──────────────────┐
         │  Governance      │
         │  Dashboard       │
         │  (Streamlit)     │
         │                  │
         │  • Audit log     │
         │  • Attack heatmap│
         │  • Review queue  │
         └──────────────────┘
```

---

## Lobster Trap — Deep Prompt Inspection

Lobster Trap is a **custom Go binary** that acts as an OpenAI-compatible reverse proxy. It borrows concepts from network security:

- **Deep Packet Inspection → Deep Prompt Inspection**: Regex-powered metadata extraction from every prompt and response. No LLM call for classification. Overhead is ~0.2–0.5 ms for short prompts and grows with length, to ~12 ms p50 for a 4 KB document (see [Performance](#performance)).
- **P4 Match-Action Tables → Programmable Policy Rules**: YAML-defined rules match on extracted fields (`risk_score`, `intent_category`, `has_mismatch`, etc.) and execute actions.
- **Three-layer ingress enforcement** (evaluated in order for every request):
  1. Match-action rule table — priority-ordered `ingress_rules` from `proxy/policy.yaml`
  2. Network policy — checks detected domains against `denied_domains` / `allowed_domains`
  3. Filesystem policy — checks detected paths against `denied_paths` using `**`-aware glob matching
- **Ingress + Egress Filtering**: Prompts are inspected before reaching the model; outputs are buffered and inspected before delivery. Streaming is denied, and a response the proxy can't decode is denied rather than forwarded uninspected.
- **Agent identity binding**: each agent sends its own key (`X-Agent-Key`, from `LT_AGENT_KEYS`). The proxy denies a call when the key doesn't match the declared `agent_id`, or when the agent declares an intent it isn't registered for in the `agents:` section of `proxy/policy.yaml`. Without this, any process on the network could claim to be any agent with any intent. The proxy refuses to start if a registered agent has no key. Unknown agents and bad keys get the same `agent_auth_failed` response. Non-chat endpoints aren't inspected, so only `GET`/`HEAD` pass through.

### Active Policy Rules

| Rule | Trigger | Action |
|------|---------|--------|
| `block_prompt_injection` | Injection patterns detected | DENY |
| `block_harm_violence` | Weapons / harm requests | DENY |
| `block_malware_request` | Malware / exploit generation | DENY |
| `block_data_exfiltration` | Exfiltration patterns | DENY |
| `block_obfuscation_evasion` | Base64 payloads, char-splitting | DENY |
| `block_sensitive_paths` | `/etc/passwd`, `.ssh/`, etc. | DENY |
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
| **analysis** | **`summarize`** | **`general`** | **ALLOW (LOG)** |
| critic | `general` | `general` | ALLOW |
| action | `code_execution` | `code_execution` | ALLOW |

---

## Human-in-the-Loop

A `HUMAN_REVIEW` verdict actually gates the run:

1. The proxy holds the call. The agent step records the review, and the LangGraph run pauses (`interrupt()`, checkpointed by `thread_id`). `POST /run` returns `status: "pending_review"`, `review_request_id`, and `thread_id`.
2. An admin approves or rejects with `POST /review/{request_id}/decide` (or from the dashboard). The decision is written to `review_decisions.jsonl` first, then the run resumes.
3. **Approve** replays the held step with `X-Sentinel-Review-Approved: <request_id>`. The proxy releases it only if the first decision on that ID is an approval made after the hold and less than 15 minutes ago, the agent, intent and forwarded body are byte-identical, and the approval hasn't been used. The audit row shows `human_review_approved` / `review_approval: accepted:<id>`. **Reject** ends the run as blocked.

Paused runs are checkpointed to SQLite (`SENTINEL_CHECKPOINT_DB`, on the `api_data` volume) for up to 24 h, so they survive an API restart. Run a single uvicorn worker (the per-key rate limiter is per process). Audit rotation is refused while any run is paused. A decision made after that is recorded with `resumed: false`.

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

## Performance

`BenchmarkProcessIngress` (`lobstertrap/internal/pipeline/bench_test.go`) times the full ingress path: DPI, identity check, rule table, and audit encoding, with the live policy. Apple M4, 2000 iterations per case:

| Prompt | p50 | p99 |
|---|---|---|
| Short benign task (128 B) | 0.15 ms | 0.52 ms |
| Injection attempt (65 B) | 0.08 ms | 0.11 ms |
| PII-bearing task (89 B) | 0.10 ms | 0.13 ms |
| Task + 1 KB document | 0.77 ms | 0.96 ms |
| Task + 4 KB document | 3.0 ms | 4.1 ms |

```bash
cd lobstertrap && go test ./internal/pipeline/ -run '^$' -bench BenchmarkProcessIngress -benchtime=2000x
```

---

## Quick Start

### Local (Docker, full stack including dashboard)

**Prerequisites:** [Docker](https://docs.docker.com/get-docker/) + Docker Compose + [Ollama](https://ollama.com/) with `llama3:latest`

```bash
ollama pull llama3:latest
ollama serve
```

```bash
# 1. Clone
git clone https://github.com/Raditya0902/sentinelmesh.git
cd sentinelmesh

# 2. Configure environment + generate one API key per role
cp .env.example .env
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
- **History isn't deleted.** `POST /audit/rotate` archives `audit.jsonl` to `audit-<timestamp>.jsonl` and starts a fresh file.

---

## Project Structure

```
sentinelmesh/
├── agents/                 # LangGraph agent definitions
│   ├── base.py             # LobsterTrapClient — single LLM call entry point
│   ├── extraction.py       # Reads documents from ChromaDB
│   ├── analysis.py         # Summarizes and classifies
│   ├── action.py           # One validated tool call per run (write-guarded)
│   ├── action_tools.py     # write_finding / notify + Pydantic validation
│   └── critic.py           # Reviews output for compliance
├── orchestrator/
│   └── main.py             # LangGraph StateGraph, RBAC preflight, human-review interrupt
├── api/
│   ├── main.py             # App factory, /run, /audit
│   ├── auth.py             # API key → role, fail-closed boot, denial auditing
│   └── review.py           # Review queue + decide/resume
├── rbac/
│   ├── roles.py            # Role definitions + namespace enforcement
│   ├── vector_store.py     # RBAC-enforced ChromaDB wrapper
│   └── seed_namespaces.py  # Seeds 17 docs across 5 namespaces
├── proxy/
│   └── policy.yaml         # Active Lobster Trap policy rules
├── dashboard/
│   └── app.py              # Streamlit governance dashboard
├── lobstertrap/            # Go source for the DPI proxy
│   ├── internal/inspector/ # DPI engine + regex pattern libraries
│   ├── internal/policy/    # Match-action table evaluation
│   ├── internal/pipeline/  # Ingress → inference → egress flow
│   └── internal/proxy/     # HTTP reverse proxy with DPI hooks
├── tests/
│   ├── run_attacks.py      # 18-check adversarial suite (+ attack_identity.py)
│   ├── test_rbac.py        # RBAC unit tests
│   ├── test_hitl.py        # Pause / approve / reject graph tests
│   └── test_pipeline.py    # Pipeline routing unit tests
├── trigger_demo.py         # Live demo script
├── docker-compose.yml      # Full 4-container stack
└── Makefile                # build / start / seed / demo / test
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent orchestration | LangGraph, LangChain |
| DPI proxy | Lobster Trap (Go) — custom-built |
| LLM backend | Groq (`openai/gpt-oss-120b`) or Ollama (`llama3:latest`) |
| Vector store | ChromaDB with RBAC namespaces |
| API | FastAPI + Pydantic |
| Dashboard | Streamlit + Plotly |
| Infrastructure | Docker, Docker Compose |
| CI/CD | GitHub Actions |

---

## Submission

- **Track:** Agent Security & AI Governance
- **Team:** Raditya0902
