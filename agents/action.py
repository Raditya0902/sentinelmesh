from .base import call_llm
from rbac import assert_write_access

SYSTEM_PROMPT = """You are an action agent. You execute writes, send notifications,
and trigger downstream systems based on confirmed analysis. You only act on explicit
instructions. All actions are logged. Scope: write access to approved namespaces only."""


def run_action(task: str, analysis_result: str, role: str) -> str:
    assert_write_access(role)
    user_prompt = f"Task: {task}\n\nAnalysis:\n{analysis_result}"
    return call_llm(
        agent_id="action-agent-v1",
        system=SYSTEM_PROMPT,
        user=user_prompt,
        declared_intent="code_execution",
    )
