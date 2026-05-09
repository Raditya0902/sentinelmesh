# Hackathon Submission: SentinelMesh

**Title:** SentinelMesh — Enterprise AI Governance Dashboard

**Short Description (255 chars):**
Policy-enforced multi-agent orchestration with real-time threat visibility. SentinelMesh uses Lobster Trap proxy to block prompt injections, PII leaks, and RBAC violations across LangGraph agents with sub-millisecond latency.

**Long Description:**
SentinelMesh is a comprehensive governance layer for autonomous AI agents. As enterprises shift from simple chatbots to complex multi-agent workflows, the risk of "The Control Gap"—where agents act without guardrails—becomes a critical blocker. 

SentinelMesh solves this by integrating Lobster Trap, a high-performance Go-based proxy, directly into the agentic lifecycle. Every LLM call (prompt and response) is inspected for intent mismatch, prompt injection patterns, and PII exfiltration. 

The system uses a LangGraph-based orchestration pipeline consisting of specialized agents (Extraction, Analysis, Action, Critic) governed by a strict RBAC layer. Data privacy is enforced at the Vector Store level using namespaced collections in ChromaDB. 

A real-time Streamlit dashboard provides administrators with a "Single Pane of Glass" for all agent activities, including a human-in-the-loop review queue for high-risk requests.

**Technology Tags:**
LangChain, LangGraph, Lobster Trap, FastAPI, Python, Docker, RBAC, ChromaDB, Streamlit

**Track:**
Track 1: Agent Security & AI Governance
