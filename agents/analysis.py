from .base import call_llm

SYSTEM_PROMPT = """You are an analysis agent. You summarize and classify information
extracted from documents. You may call external read-only APIs when needed.
You do not write to any systems or take direct actions."""


def run_analysis(task: str, extracted_data: str) -> str:
    user_prompt = f"Task: {task}\n\nExtracted data:\n{extracted_data}"
    return call_llm(
        agent_id="analysis-agent-v1",
        system=SYSTEM_PROMPT,
        user=user_prompt,
        declared_intent="summarize",
    )
