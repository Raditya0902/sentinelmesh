# SentinelMesh — Enterprise AI Governance

> **Policy-Enforced Multi-Agent Orchestration with Real-Time Threat Visibility**
> Hackathon: Transforming Enterprise Through AI | Track 1: Agent Security & AI Governance

SentinelMesh is a multi-agent LangGraph system where every agent action passes through
**Lobster Trap** (a deep prompt inspection proxy) for real-time policy enforcement,
attack blocking, and compliance-grade audit trails.

## 🛡️ The Problem
As enterprises deploy autonomous agents, they face "The Control Gap":
1. **Agents act without guardrails:** A simple prompt injection can leak PII or trigger unauthorized actions.
2. **Invisible Intent:** Traditional firewalls don't understand LLM intent or agent roles.
3. **No Audit Trail:** Compliance requires knowing exactly *why* an agent was blocked, in real-time.

SentinelMesh solves this by placing a sub-millisecond, regex-powered DPI proxy between the agents and the LLM.

## 🏗️ Architecture

```text
User Request
     ↓
Orchestrator Agent (LangGraph)
     ↓
┌─────────────────────────────────────────┐
│           Lobster Trap Proxy             │
│  Extracts: intent, risk_score, PII,     │
│  injections, credentials, exfiltration  │
│  Actions: ALLOW / DENY / QUARANTINE /   │
│           LOG / HUMAN_REVIEW            │
└─────────────────────────────────────────┘
     ↓              ↓              ↓
Extraction      Analysis       Action
  Agent          Agent          Agent
     ↓
RBAC Layer (ChromaDB namespace + role scoping)
     ↓
Governance Dashboard (Streamlit)
Audit log | Blocked attacks | Risk heatmap
```

## 🚀 Quick Start

### Prerequisites
- Python 3.13
- Docker & Docker Compose
- Ollama (running locally with `llama3:latest`)

### Setup
1. **Clone the repo**
2. **Start the stack**
   ```bash
   make start
   ```
3. **Seed the database**
   ```bash
   make seed
   ```
4. **View the Dashboard**
   Open `http://localhost:8501`

## ⚔️ Attack Scenarios

SentinelMesh is designed to catch 3 core attack vectors:

1. **Prompt Injection:** An agent is instructed to ignore its system prompt.
   - **Result:** Lobster Trap triggers `block_prompt_injection` → `DENY`.
2. **PII Exfiltration:** An agent attempts to output a Social Security Number.
   - **Result:** Lobster Trap triggers `block_pii_exfiltration` → `DENY`.
3. **Cross-Role Data Access:** An analyst attempts to access a restricted 'Finance' namespace.
   - **Result:** RBAC Layer blocks the request before it even reaches the LLM.

## 🛠️ Tech Stack
- **Orchestration:** LangGraph, LangChain
- **Proxy:** Lobster Trap (Go)
- **Database:** ChromaDB (Vector Store with RBAC namespaces)
- **API:** FastAPI
- **UI:** Streamlit
- **Infrastructure:** Docker, Docker Compose

## 👥 Submission Info
- **Team:** SentinelMesh
- **Track:** Agent Security & AI Governance
- **Deployment:** [Live Demo URL](https://sentinelmesh.up.railway.app)
