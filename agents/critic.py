from .base import call_llm

SYSTEM_PROMPT = """You are a critic agent. You review the outputs of other agents and
flag any concerns: policy violations, factual errors, scope creep, or unsafe actions.
Read-only access. Return a JSON object with fields: approved (bool), concerns (list[str])."""


def run_critic(task: str, agent_output: str, agent_name: str) -> str:
    user_prompt = (
        f"Task: {task}\n\nAgent: {agent_name}\n\nOutput to review:\n{agent_output}"
    )
    return call_llm(
        agent_id="critic-agent-v1",
        system=SYSTEM_PROMPT,
        user=user_prompt,
        declared_intent="general",
    )
