"""Single entry point for every agent LLM call. All calls route through Lobster Trap.

Each call carries:
  * the agent's identity claim (``_lobstertrap.agent_id`` + ``declared_intent``), and
  * the agent's secret key (``X-Agent-Key``, from ``LT_AGENT_KEYS``) so the proxy can
    verify the claim instead of trusting it.

The proxy answers HTTP 200 even when it blocks. DENY comes back as ``[SENTINEL] ...``
text (returned to the caller unchanged); HUMAN_REVIEW raises ``HumanReviewRequired`` so
the orchestrator can pause the run until a human decides.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from typing import Any, Optional

from openai import OpenAI

from config import get_settings

AGENT_KEY_HEADER = "X-Agent-Key"
REVIEW_APPROVAL_HEADER = "X-Sentinel-Review-Approved"
AGENT_KEYS_ENV = "LT_AGENT_KEYS"
VERDICT_HUMAN_REVIEW = "HUMAN_REVIEW"
BLOCK_PREFIXES = ("[SENTINEL]", "[LOBSTER TRAP]")

# Set only while the orchestrator replays a human-approved request.
_approved_review_id: ContextVar[Optional[str]] = ContextVar("approved_review_id", default=None)


def is_sentinel_blocked(text: str) -> bool:
    """Lobster Trap answers HTTP 200 for blocks; the block is the response text."""
    return text.strip().startswith(BLOCK_PREFIXES)


class HumanReviewRequired(Exception):
    """The proxy held this call for human review (verdict HUMAN_REVIEW)."""

    def __init__(self, message: str, request_id: str, agent_id: str) -> None:
        super().__init__(message)
        self.request_id = request_id
        self.agent_id = agent_id


@contextmanager
def review_approval(request_id: Optional[str]) -> Iterator[None]:
    """Attach ``X-Sentinel-Review-Approved: <request_id>`` to LLM calls in this block.

    The proxy releases a held request only if a human approved that request ID and the
    replayed prompt and agent are identical to the original.
    """
    token = _approved_review_id.set(request_id)
    try:
        yield
    finally:
        _approved_review_id.reset(token)


def _agent_key(agent_id: str) -> Optional[str]:
    raw = get_settings().lt_agent_keys.strip()
    if not raw:
        return None
    try:
        keys = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f'{AGENT_KEYS_ENV} must be a JSON object of {{"<agent_id>": "<key>"}} ({exc.msg})'
        ) from exc
    if not isinstance(keys, dict):
        raise ValueError(f'{AGENT_KEYS_ENV} must be a JSON object of {{"<agent_id>": "<key>"}}')
    key = keys.get(agent_id)
    return key if isinstance(key, str) and key else None


MAX_CACHED_CLIENTS = 4


@lru_cache(maxsize=MAX_CACHED_CLIENTS)
def _client_for(base_url: str, api_key: str, timeout: float, max_retries: int) -> OpenAI:
    """One OpenAI client (and its HTTP connection pool) per proxy URL + key, per process."""
    return OpenAI(base_url=base_url, api_key=api_key, timeout=timeout, max_retries=max_retries)


def _make_client() -> OpenAI:
    s = get_settings()
    return _client_for(f"{s.lobster_trap_url}/v1", s.llm_api_key,
                       s.llm_timeout_seconds, s.llm_max_retries)


def _request_headers(agent_id: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    key = _agent_key(agent_id)
    if key:
        headers[AGENT_KEY_HEADER] = key
    approval = _approved_review_id.get()
    if approval:
        headers[REVIEW_APPROVAL_HEADER] = approval
    return headers


class LobsterTrapClient:
    """Thin wrapper that routes LLM calls through Lobster Trap and attaches agent metadata."""

    def __init__(
        self,
        agent_id: str,
        declared_intent: str = "general",
        client: Optional[OpenAI] = None,
    ) -> None:
        self.agent_id = agent_id
        self.declared_intent = declared_intent
        self._client = client if client is not None else _make_client()

    def chat(self, messages: list[dict], **kwargs: Any) -> str:
        model = get_settings().llm_model
        extra_body = {
            "_lobstertrap": {
                "agent_id": self.agent_id,
                "declared_intent": self.declared_intent,
            }
        }
        raw = self._client_for_call().chat.completions.with_raw_response.create(
            model=model,
            messages=messages,
            extra_body=extra_body,
            extra_headers=_request_headers(self.agent_id),
            **kwargs,
        )
        response = raw.parse()
        text = (response.choices[0].message.content or "") if response.choices else ""
        self._raise_if_held(raw.http_response.json(), text)
        return text

    def _client_for_call(self) -> OpenAI:
        """No retries while replaying a human-approved request: the proxy releases an
        approval once, so a retry after a lost response would only be held again."""
        if _approved_review_id.get():
            return self._client.with_options(max_retries=0)
        return self._client

    def _raise_if_held(self, body: Any, text: str) -> None:
        report = body.get("_lobstertrap") if isinstance(body, dict) else None
        if not isinstance(report, dict) or report.get("verdict") != VERDICT_HUMAN_REVIEW:
            return
        request_id = report.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise RuntimeError("Lobster Trap returned HUMAN_REVIEW without a request_id")
        raise HumanReviewRequired(text, request_id, self.agent_id)


def call_llm(
    agent_id: str,
    system: str,
    user: str,
    declared_intent: str = "general",
    **kwargs: Any,
) -> str:
    client = LobsterTrapClient(agent_id=agent_id, declared_intent=declared_intent)
    return client.chat(
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        **kwargs,
    )
