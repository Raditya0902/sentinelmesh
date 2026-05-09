from rbac.vector_store import NamespacedVectorStore

from .base import call_llm

SYSTEM_PROMPT = """You are an extraction agent. Your only job is to parse and extract
structured information from documents. You do not summarize, analyze, or take actions.
Return extracted data in a structured format. Read-only access."""


def run_extraction(
    task: str,
    document: str,
    role: str = "readonly",
    namespace: str = "general",
) -> str:
    context_block = _fetch_context(role, namespace, task)
    user_prompt = f"{context_block}Task: {task}\n\nDocument:\n{document}"
    return call_llm(
        agent_id="extraction-agent-v1",
        system=SYSTEM_PROMPT,
        user=user_prompt,
        declared_intent="data_access",
    )


def _fetch_context(role: str, namespace: str, query: str) -> str:
    store = NamespacedVectorStore()
    try:
        results = store.query(role, namespace, query, n_results=3)
    except PermissionError:
        return ""
    if not results:
        return ""
    lines = "\n".join(f"- {r['document']}" for r in results)
    return f"[CONTEXT from knowledge base]\n{lines}\n\n"
