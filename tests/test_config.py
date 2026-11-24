"""config.py settings, the cached OpenAI client, and the redacted step-failure text."""

import logging

import pytest

import agents.base as base
import orchestrator.main as orch
from config import get_settings, load_env_file


def test_settings_read_from_environment(monkeypatch):
    monkeypatch.setenv("LOBSTER_TRAP_URL", "http://proxy.test:9")
    monkeypatch.setenv("LLM_MODEL", "m-1")
    monkeypatch.setenv("CHROMA_PORT", "1234")

    s = get_settings()

    assert s.lobster_trap_url == "http://proxy.test:9"
    assert s.llm_model == "m-1"
    assert s.chroma_port == 1234


def test_llm_api_key_prefers_groq_then_openai(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    assert get_settings().llm_api_key == "sk-openai"

    monkeypatch.setenv("GROQ_API_KEY", "gsk-groq")
    assert get_settings().llm_api_key == "gsk-groq"


def test_llm_api_key_placeholder_when_unset(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert get_settings().llm_api_key == "not-needed"


def test_load_env_file_missing_returns_false(tmp_path):
    assert load_env_file(tmp_path / "absent.env") is False


def test_openai_client_is_cached_per_url_and_key(monkeypatch):
    built = []

    class FakeOpenAI:
        def __init__(self, base_url, api_key, timeout, max_retries):
            built.append((base_url, api_key, timeout))

    monkeypatch.setattr(base, "OpenAI", FakeOpenAI)
    base._client_for.cache_clear()
    monkeypatch.setenv("LOBSTER_TRAP_URL", "http://a.test")
    monkeypatch.setenv("GROQ_API_KEY", "k1")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "7")

    first = base.LobsterTrapClient("critic-agent-v1")._client
    second = base.LobsterTrapClient("analysis-agent-v1")._client
    monkeypatch.setenv("LOBSTER_TRAP_URL", "http://b.test")
    third = base.LobsterTrapClient("critic-agent-v1")._client

    assert first is second
    assert third is not first
    assert built == [("http://a.test/v1", "k1", 7.0), ("http://b.test/v1", "k1", 7.0)]
    base._client_for.cache_clear()


def test_step_failure_hides_exception_text_but_logs_it(monkeypatch, caplog):
    def boom(**_):
        raise RuntimeError("connection refused to /internal/secret-host:5432")

    monkeypatch.setattr(orch, "run_extraction", boom)
    with caplog.at_level(logging.ERROR, logger="orchestrator.main"):
        result = orch.run_pipeline(task="t", document="d", role="analyst", namespace="general")

    assert result["blocked"] is True
    assert result["error"].startswith("extraction failed: RuntimeError (error_id=")
    assert "secret-host" not in result["error"]
    error_id = result["error"].split("error_id=")[1].rstrip(")")
    logged = "\n".join(r.getMessage() + (r.exc_text or "") for r in caplog.records)
    assert error_id in logged
    assert any(r.exc_info for r in caplog.records), "full traceback must be logged server-side"


@pytest.mark.parametrize("prefix", ["[SENTINEL]", "[LOBSTER TRAP]"])
def test_block_prefixes_still_detected(prefix):
    assert base.is_sentinel_blocked(f"  {prefix} Blocked")
