import os
from typing import Any

from openai import OpenAI


def _make_client() -> OpenAI:
    url = os.getenv("LOBSTER_TRAP_URL", "http://localhost:8080")
    api_key = os.getenv("GROQ_API_KEY") or os.getenv("OPENAI_API_KEY") or "not-needed"
    return OpenAI(base_url=f"{url}/v1", api_key=api_key)


class LobsterTrapClient:
    """Thin wrapper that routes LLM calls through Lobster Trap and attaches agent metadata."""

    def __init__(self, agent_id: str, declared_intent: str = "general"):
        self.agent_id = agent_id
        self.declared_intent = declared_intent
        self._client = _make_client()

    def chat(self, messages: list[dict], **kwargs: Any) -> str:
        model = os.getenv("LLM_MODEL", "llama3:latest")
        extra_body = {
            "_lobstertrap": {
                "agent_id": self.agent_id,
                "declared_intent": self.declared_intent,
            }
        }
        response = self._client.chat.completions.create(
            model=model,
            messages=messages,
            extra_body=extra_body,
            **kwargs,
        )
        return response.choices[0].message.content or "" if response.choices else ""


def call_llm(agent_id: str, system: str, user: str, declared_intent: str = "general") -> str:
    client = LobsterTrapClient(agent_id=agent_id, declared_intent=declared_intent)
    return client.chat(
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
    )
