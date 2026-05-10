# SentinelMesh

> **Policy-Enforced Multi-Agent Orchestration with Real-Time Threat Visibility**
> Hackathon: Transforming Enterprise Through AI — Track 1: Agent Security & AI Governance

SentinelMesh is a production-grade governance layer for autonomous AI agents. Every LLM call — prompt and response — passes through **Lobster Trap**, a custom Go-based Deep Prompt Inspection proxy, before it ever reaches the model. The result: real-time attack blocking, compliance-grade audit trails, and a live governance dashboard, all with sub-millisecond overhead.

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
│              Orchestrator (LangGraph)                 │
│         RBAC preflight — validates role + namespace   │
└──────────────────────────┬───────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────┐
│                  Lobster Trap Proxy                   │
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

- **Deep Packet Inspection → Deep Prompt Inspection**: Regex-powered metadata extraction from every prompt and response. No LLM call for classification — runs in under 1ms.
- **P4 Match-Action Tables → Programmable Policy Rules**: YAML-defined rules match on extracted fields (`risk_score`, `intent_category`, `has_mismatch`, etc.) and execute actions.
- **Three-layer ingress enforcement** (evaluated in order for every request):
  1. Match-action rule table — priority-ordered `ingress_rules` from `proxy/policy.yaml`
  2. Network policy — checks detected domains against `denied_domains` / `allowed_domains`
  3. Filesystem policy — checks detected paths against `denied_paths` using `**`-aware glob matching
- **Ingress + Egress Filtering**: Prompts are inspected before reaching the model; outputs are buffered and inspected before delivery. Streaming is denied to prevent egress inspection bypass.

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
| `human_review_mismatch` | Declared intent ≠ detected intent | HUMAN_REVIEW |
| `log_all_agent_actions` | Every agent call | LOG |

### Intent Mismatch Detection

Each agent declares its intent in the request header (`_lobstertrap.declared_intent`). Lobster Trap independently classifies the actual intent via DPI. When they diverge, the request is flagged for human review:

| Agent | Declared | DPI Detects | Result |
|-------|----------|-------------|--------|
| extraction | `data_access` | `data_access` | ALLOW |
| **analysis** | **`summarize`** | **`data_access`** | **HUMAN_REVIEW** |
| critic | `general` | `general` | ALLOW |
| action | `code_execution` | `code_execution` | ALLOW |

---

## RBAC — Three Enforcement Layers

Role-based access control is enforced independently at three layers. Any single layer can block a request:

```
1. Orchestrator node     — validates role + namespace before any LLM call
2. NamespacedVectorStore — RBAC check before every ChromaDB query or upsert
3. Lobster Trap policy   — role-scoped rules in proxy/policy.yaml
```

**Roles and namespace access:**

| Role | Namespaces | Write |
|------|-----------|-------|
| `admin` | all | yes |
| `analyst` | general, legal | no |
| `auditor` | audit | no |
| `readonly` | general | no |

---

## Governance Dashboard

The Streamlit dashboard provides a real-time single pane of glass:

- **Color-coded audit table** — DENY (red), HUMAN_REVIEW (blue), ALLOW/LOG (green)
- **Event timeline** — scatter plot of every agent action over time
- **Attack frequency chart** — bar chart of events by agent + action type
- **Human review queue** — approve or reject flagged requests; decisions persisted across restarts

---

## Demo: 14-Vector Adversarial Test Suite

```bash
python trigger_demo.py
```

Fires 14 scenarios against the live API:

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
| 14 | RBAC — invalid role `hacker` | DENY |

---

## Quick Start

### Option A — Cloud (Railway, no local setup)

The full backend (FastAPI + Lobster Trap + Groq) is deployed and live:

```
https://sentinelmesh-production.up.railway.app
```

```bash
# Health check
curl https://sentinelmesh-production.up.railway.app/health

# Run the pipeline
curl -s -X POST https://sentinelmesh-production.up.railway.app/run \
  -H "Content-Type: application/json" \
  -d '{"task":"Summarize the quarterly report","document":"Q1 revenue $5M, +20% YoY","role":"analyst","namespace":"general"}'

# Tail the audit log (add -H "X-Sentinel-Key: <token>" if SENTINEL_API_KEY is set)
curl https://sentinelmesh-production.up.railway.app/audit?limit=10

# Run all 14 attack scenarios against the live API
API_URL=https://sentinelmesh-production.up.railway.app python trigger_demo.py
```

> **Note:** The Streamlit governance dashboard runs locally only (Docker). The cloud deployment exposes the FastAPI backend and Lobster Trap proxy.

---

### Option B — Local (Docker, full stack including dashboard)

**Prerequisites:** [Docker](https://docs.docker.com/get-docker/) + Docker Compose + [Ollama](https://ollama.com/) with `llama3:latest`

```bash
ollama pull llama3:latest
ollama serve
```

```bash
# 1. Clone
git clone https://github.com/Raditya0902/sentinelmesh.git
cd sentinelmesh

# 2. Configure environment
cp .env.example .env

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
GET    /health                      — liveness check
POST   /run                         — trigger the agent pipeline
GET    /audit?limit=50              — tail the audit log            *
DELETE /audit                       — clear audit + decisions logs  *
GET    /review/queue?status=pending — list HUMAN_REVIEW items       *
POST   /review/{request_id}/decide  — approve or reject a flagged item *
```

`*` Requires `X-Sentinel-Key: <token>` header when `SENTINEL_API_KEY` env var is set.  
Leave `SENTINEL_API_KEY` empty for open demo mode.

---

## Project Structure

```
sentinelmesh/
├── agents/                 # LangGraph agent definitions
│   ├── base.py             # LobsterTrapClient — single LLM call entry point
│   ├── extraction.py       # Reads documents from ChromaDB
│   ├── analysis.py         # Summarizes and classifies
│   ├── action.py           # Writes / notifies (write-guarded)
│   └── critic.py           # Reviews output for compliance
├── orchestrator/
│   └── main.py             # LangGraph StateGraph + RBAC preflight
├── api/
│   └── main.py             # FastAPI routes + human review queue
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
│   ├── run_attacks.py      # 14-vector adversarial test suite
│   ├── test_rbac.py        # RBAC unit tests
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
| LLM backend | Groq (`llama-3.3-70b-versatile`) — cloud; Ollama (`llama3:latest`) — local |
| Vector store | ChromaDB with RBAC namespaces |
| API | FastAPI + Pydantic |
| Dashboard | Streamlit + Plotly |
| Infrastructure | Docker, Docker Compose, Railway |
| CI/CD | GitHub Actions |

---

## Submission

- **Track:** Agent Security & AI Governance
- **Team:** Raditya0902
- **Live Demo:** [sentinelmesh.up.railway.app](https://sentinelmesh.up.railway.app)
