# SentinelMesh Architecture

## 1. Governance Proxy (Lobster Trap)
Lobster Trap acts as a Deep Prompt Inspection (DPI) layer. It sits between the LangGraph agents and the LLM (Ollama/Groq). 

- **Low latency, length-dependent:** Go regex DPI takes ~0.2–0.5 ms for short prompts and ~12 ms p50 for a 4 KB document (see `docs/threat-model.md`).
- **Agent identity binding:** Each agent authenticates with its own key (`X-Agent-Key`). The proxy denies unknown agents, mismatched keys, and intents an agent isn't registered for (`agents:` in `proxy/policy.yaml`).
- **Intent Mapping:** Agents declare their intent (e.g., "Summarizing text") and Lobster Trap detects their actual intent via patterns. A mismatch triggers a `HUMAN_REVIEW` action.
- **Risk Scoring:** Assigns a risk score to every prompt and response. Scores > 0.8 are automatically quarantined.
- **Three-layer enforcement in `ProcessIngress`:**
  1. Match-action rule table (`ingress_rules` in `proxy/policy.yaml`) — first-match-wins, evaluated by priority.
  2. Network policy (`network.denied_domains`, `network.allowed_domains`) — checked if the rule table returns ALLOW or LOG.
  3. Filesystem policy (`filesystem.denied_paths`) — checked after network, supports `**` recursive glob patterns.
- **Egress inspection:** Model output is buffered and inspected before delivery. Streaming requests are denied to ensure egress DPI cannot be bypassed.

## 2. Multi-Agent Orchestration (LangGraph)
We use a StateGraph to manage the agentic lifecycle:
1. **Orchestrator:** Validates RBAC and routes the request.
2. **Extraction Agent:** Retrieves context from ChromaDB.
3. **Analysis Agent:** Processes the data and generates insights.
4. **Action Agent:** Proposes one JSON tool call (`write_finding` into the `findings` namespace, or `notify`), validated with Pydantic and re-checked against RBAC before it runs. Gated by `Role.can_write`.
5. **Critic Agent:** Reviews the output for compliance and quality.

## 3. RBAC & Data Privacy
- **Namespaced Vector Store:** We extend ChromaDB to enforce role-based collection access. An 'analyst' cannot query the 'hr' collection.
- **Write Guards:** `assert_write_access` is called before any state-mutating action is performed.

## 4. Visibility & Governance Dashboard
- **Real-time Audit:** Streamlit dashboard fetches audit data from `GET /audit?limit=1000` (FastAPI tails the JSONL log with bounded memory). Auto-refreshes every 3 seconds.
- **Human-in-the-Loop:** A HUMAN_REVIEW verdict pauses the LangGraph run (`interrupt()` + checkpointer). An admin decision is recorded in `review_decisions.jsonl`, then the run resumes. Approve replays the held call with `X-Sentinel-Review-Approved`, which the proxy honours once, for the same agent and identical prompt, only if the approval post-dates the hold. Reject ends the run as blocked. Paused runs are in memory and don't survive an API restart.
- **Safe log management:** The dashboard's "Rotate Audit Log" action calls `POST /audit/rotate` (admin only). It archives `audit.jsonl` and `review_decisions.jsonl` to timestamped files, then truncates the originals in place. Audit history is never deleted. It uses copy-then-truncate rather than rename because the Go proxy holds the file open with `O_APPEND`, and a rename would send its writes into the archive.
