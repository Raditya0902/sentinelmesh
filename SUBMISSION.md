# Hackathon Submission (archived)

SentinelMesh started as an entry to **Transforming Enterprise Through AI**, Track 1: Agent Security & AI Governance. The demo was on May 19, 2026. The hackathon is over, and the project is now maintained as a portfolio project (see [README.md](README.md)). This file keeps the submission materials for reference.

**Title:** SentinelMesh: Policy-Enforced Multi-Agent Orchestration

**Track:** Track 1: Agent Security & AI Governance

## Short description (≤255 chars)

LangGraph multi-agent pipeline where every LLM call passes through the Lobster Trap DPI proxy: key-bound roles and agent identities, RBAC'd ChromaDB namespaces, human-in-the-loop approval that really pauses runs, and an archive-only audit trail.

## Long description

SentinelMesh is a governance layer for multi-agent AI. As enterprises move from chatbots to autonomous agent workflows, a "control gap" opens: agents read data, call models and take actions with no policy in the loop. SentinelMesh closes that gap by routing every agent LLM call through Lobster Trap, the sponsor's Go Deep Prompt Inspection proxy, which inspects both the prompt and the model's response.

A LangGraph pipeline (extraction, analysis, critic and action agents) runs behind a FastAPI governance API. Callers get their role only from their API key. Agents authenticate to the proxy with their own keys and may declare only the intents they are registered for, so a caller can't spoof a role or an intent to dodge a rule. Regex DPI blocks known prompt-injection, malware, exfiltration, sensitive-path and obfuscation patterns on ingress, and PII and credential leaks on egress. Data access is scoped by ChromaDB namespaces, and the role is re-checked on every query and write.

When the proxy flags an intent mismatch, the run really pauses. It is checkpointed to SQLite until an admin approves or rejects it. An approval releases the held call exactly once, and only for the identical request. Every decision lands in an archive-only audit log that a Streamlit dashboard and the proxy's live dashboard both show. 158 tests and the non-LLM attack checks run in CI; the full 18-check attack suite runs locally against a live LLM.

## Technology tags

LangChain, LangGraph, Lobster Trap, FastAPI, Python, Go, Docker, ChromaDB, Streamlit, RBAC, SQLite, GitHub Actions

## Original checklist (final state)

- [x] Public GitHub repo with README and architecture diagram ([docs/architecture.md](docs/architecture.md))
- [x] 6-slide PDF presentation (SentinelMesh_v2.pdf, 7 slides including the cover; not checked into this repo)
- [x] Short description (255 chars max)
- [x] Long description (100+ words)
- [x] Technology tags
- [ ] 3–5 min demo video (dropped after the hackathon)
- [ ] Cover image, 1200x630 (dropped after the hackathon)
