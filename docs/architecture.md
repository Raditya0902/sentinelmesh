# SentinelMesh Architecture

## 1. Governance Proxy (Lobster Trap)
Lobster Trap acts as a Deep Prompt Inspection (DPI) layer. It sits between the LangGraph agents and the LLM (Ollama/OpenAI). 

- **Sub-millisecond latency:** Uses Go-based regex matching for rapid scanning.
- **Intent Mapping:** Agents declare their intent (e.g., "Summarizing text") and Lobster Trap detects their actual intent via patterns. A mismatch triggers a `HUMAN_REVIEW` action.
- **Risk Scoring:** Assigns a risk score to every prompt and response. Scores > 0.8 are automatically quarantined.

## 2. Multi-Agent Orchestration (LangGraph)
We use a StateGraph to manage the agentic lifecycle:
1. **Orchestrator:** Validates RBAC and routes the request.
2. **Extraction Agent:** Retrieves context from ChromaDB.
3. **Analysis Agent:** Processes the data and generates insights.
4. **Action Agent:** Performs side-effects (notifications, writes). Gated by `Role.can_write`.
5. **Critic Agent:** Reviews the output for compliance and quality.

## 3. RBAC & Data Privacy
- **Namespaced Vector Store:** We extend ChromaDB to enforce role-based collection access. An 'analyst' cannot query the 'hr' collection.
- **Write Guards:** `assert_write_access` is called before any state-mutating action is performed.

## 4. Visibility & Governance Dashboard
- **Real-time Audit:** Streamlit dashboard tails the Lobster Trap JSONL log.
- **Human-in-the-Loop:** High-risk or ambiguous requests are held in a queue. A human administrator must approve or reject the request via the dashboard before the pipeline continues (or for logging the decision).
