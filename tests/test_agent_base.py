"""LobsterTrapClient: identity headers, HUMAN_REVIEW detection, approval replay."""

import json

import httpx
import pytest
from openai import OpenAI

from agents.base import (
    AGENT_KEY_HEADER,
    REVIEW_APPROVAL_HEADER,
    HumanReviewRequired,
    LobsterTrapClient,
    review_approval,
)

AGENT_KEYS = {"critic-agent-v1": "critic-secret-0123456789abc"}


def _completion(content: str, verdict: str = "ALLOW", request_id: str = "req-7") -> dict:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "test",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": content}}],
        "_lobstertrap": {"request_id": request_id, "verdict": verdict},
    }


def _client(handler, monkeypatch) -> LobsterTrapClient:
    monkeypatch.setenv("LT_AGENT_KEYS", json.dumps(AGENT_KEYS))
    openai_client = OpenAI(
        base_url="http://proxy.test/v1",
        api_key="unused",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return LobsterTrapClient("critic-agent-v1", "general", client=openai_client)


def test_sends_agent_key_and_no_approval_header_by_default(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=_completion("fine"))

    text = _client(handler, monkeypatch).chat([{"role": "user", "content": "hi"}])

    assert text == "fine"
    assert seen[AGENT_KEY_HEADER.lower()] == AGENT_KEYS["critic-agent-v1"]
    assert REVIEW_APPROVAL_HEADER.lower() not in seen


def test_human_review_verdict_raises_with_request_id(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_completion(
            "[LOBSTER TRAP] Request requires human review before processing.",
            verdict="HUMAN_REVIEW", request_id="req-42"))

    with pytest.raises(HumanReviewRequired) as info:
        _client(handler, monkeypatch).chat([{"role": "user", "content": "hi"}])

    assert info.value.request_id == "req-42"
    assert info.value.agent_id == "critic-agent-v1"
    assert str(info.value).startswith("[LOBSTER TRAP]")


def test_deny_verdict_is_returned_as_text_not_raised(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_completion("[SENTINEL] Blocked: x", verdict="DENY"))

    text = _client(handler, monkeypatch).chat([{"role": "user", "content": "hi"}])

    assert text.startswith("[SENTINEL]")


def test_review_approval_context_adds_header(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=_completion("approved output"))

    client = _client(handler, monkeypatch)
    with review_approval("req-42"):
        client.chat([{"role": "user", "content": "hi"}])

    assert seen[REVIEW_APPROVAL_HEADER.lower()] == "req-42"


def test_review_approval_context_is_scoped(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.clear()
        seen.update(request.headers)
        return httpx.Response(200, json=_completion("ok"))

    client = _client(handler, monkeypatch)
    with review_approval("req-42"):
        pass
    client.chat([{"role": "user", "content": "hi"}])

    assert REVIEW_APPROVAL_HEADER.lower() not in seen


def test_missing_agent_key_sends_no_key_header(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json=_completion("ok"))

    client = _client(handler, monkeypatch)
    monkeypatch.setenv("LT_AGENT_KEYS", "{}")
    client.chat([{"role": "user", "content": "hi"}])

    assert AGENT_KEY_HEADER.lower() not in seen


def test_malformed_agent_keys_raise_clear_error(monkeypatch):
    client = _client(lambda r: httpx.Response(200, json=_completion("ok")), monkeypatch)
    monkeypatch.setenv("LT_AGENT_KEYS", "not json")

    with pytest.raises(ValueError, match="LT_AGENT_KEYS"):
        client.chat([{"role": "user", "content": "hi"}])


def test_human_review_without_request_id_is_an_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        body = _completion("[LOBSTER TRAP] held", verdict="HUMAN_REVIEW")
        del body["_lobstertrap"]["request_id"]
        return httpx.Response(200, json=body)

    with pytest.raises(RuntimeError, match="request_id"):
        _client(handler, monkeypatch).chat([{"role": "user", "content": "hi"}])
