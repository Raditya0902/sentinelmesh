"""Action agent: structured tool calls, validation, RBAC, and auditing."""

import json

import pytest

import agents.action as action
from agents.action_tools import (
    FINDINGS_NAMESPACE,
    NotifyCall,
    ToolCallRejected,
    WriteFindingCall,
    execute_tool,
    parse_tool_call,
)


class FakeStore:
    def __init__(self) -> None:
        self.upserts: list[dict] = []

    def upsert(self, role_name, namespace, documents, ids, metadatas=None) -> None:
        self.upserts.append({"role": role_name, "namespace": namespace,
                             "documents": documents, "ids": ids, "metadatas": metadatas})


def _read_jsonl(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


# ── parsing ──────────────────────────────────────────────────────────────────

def test_parses_write_finding():
    call = parse_tool_call('{"tool": "write_finding", "args": {"namespace": "findings", "text": "No risks."}}')
    assert isinstance(call, WriteFindingCall)
    assert call.args.text == "No risks."


def test_parses_notify():
    call = parse_tool_call('{"tool": "notify", "args": {"channel": "compliance", "message": "Done."}}')
    assert isinstance(call, NotifyCall)


def test_parses_json_wrapped_in_code_fence():
    raw = '```json\n{"tool": "notify", "args": {"channel": "ops", "message": "hi"}}\n```'
    assert isinstance(parse_tool_call(raw), NotifyCall)


@pytest.mark.parametrize("raw, reason", [
    ('{"tool": "delete_everything", "args": {}}', "unknown tool"),
    ('not json at all', "not valid JSON"),
    ('{"tool": "notify", "args": {"channel": "ops"}}', "invalid arguments"),
    ('{"tool": "notify", "args": {"channel": "Bad Channel!", "message": "x"}}', "invalid arguments"),
    ('{"tool": "notify", "args": {"channel": "ops", "message": "x", "extra": 1}}', "invalid arguments"),
    ('["notify"]', "JSON object"),
])
def test_rejects_bad_tool_calls(raw, reason):
    with pytest.raises(ToolCallRejected, match=reason):
        parse_tool_call(raw)


# ── execution ────────────────────────────────────────────────────────────────

def test_write_finding_upserts_into_findings_namespace(tmp_path):
    store = FakeStore()
    call = parse_tool_call('{"tool": "write_finding", "args": {"namespace": "findings", "text": "Clean."}}')

    result = execute_tool(call, "admin", store=store, notifications_path=tmp_path / "n.jsonl")

    assert result.status == "ok"
    assert store.upserts[0]["namespace"] == FINDINGS_NAMESPACE
    assert store.upserts[0]["documents"] == ["Clean."]
    assert store.upserts[0]["role"] == "admin"


def test_write_finding_outside_findings_namespace_rejected(tmp_path):
    store = FakeStore()
    call = parse_tool_call('{"tool": "write_finding", "args": {"namespace": "hr", "text": "Raise salaries."}}')

    with pytest.raises(ToolCallRejected, match="namespace"):
        execute_tool(call, "admin", store=store, notifications_path=tmp_path / "n.jsonl")
    assert store.upserts == []


def test_write_finding_requires_write_role(tmp_path):
    store = FakeStore()
    call = parse_tool_call('{"tool": "write_finding", "args": {"namespace": "findings", "text": "x"}}')

    with pytest.raises(ToolCallRejected, match="analyst"):
        execute_tool(call, "analyst", store=store, notifications_path=tmp_path / "n.jsonl")
    assert store.upserts == []


def test_notify_appends_to_notifications_log(tmp_path):
    path = tmp_path / "notifications.jsonl"
    call = parse_tool_call('{"tool": "notify", "args": {"channel": "compliance", "message": "Report ready."}}')

    result = execute_tool(call, "admin", store=FakeStore(), notifications_path=path)

    assert result.status == "ok"
    [entry] = _read_jsonl(path)
    assert entry["channel"] == "compliance"
    assert entry["message"] == "Report ready."
    assert entry["role"] == "admin"


# ── run_action end to end (LLM mocked) ───────────────────────────────────────

def test_run_action_executes_and_audits(tmp_path, monkeypatch, _isolated_audit_log):
    monkeypatch.setattr(action, "call_llm", lambda **_: '{"tool": "write_finding", "args": {"namespace": "findings", "text": "OK"}}')
    store = FakeStore()

    out = action.run_action("task", "analysis", "admin", store=store, notifications_path=tmp_path / "n.jsonl")

    assert json.loads(out)["tool"] == "write_finding"
    assert len(store.upserts) == 1
    [entry] = _read_jsonl(_isolated_audit_log)
    assert entry["rule_name"] == "action_tool_executed"
    assert entry["action"] == "ALLOW"
    assert entry["tool"] == "write_finding"


def test_run_action_unknown_tool_denied_and_audited(tmp_path, monkeypatch, _isolated_audit_log):
    monkeypatch.setattr(action, "call_llm", lambda **_: '{"tool": "rm_rf", "args": {}}')
    store = FakeStore()

    with pytest.raises(ToolCallRejected):
        action.run_action("task", "analysis", "admin", store=store, notifications_path=tmp_path / "n.jsonl")

    assert store.upserts == []
    [entry] = _read_jsonl(_isolated_audit_log)
    assert entry["rule_name"] == "action_tool_denied"
    assert entry["action"] == "DENY"
    assert "unknown tool" in entry["deny_message"]


def test_run_action_passes_through_proxy_block(tmp_path, monkeypatch, _isolated_audit_log):
    monkeypatch.setattr(action, "call_llm", lambda **_: "[SENTINEL] Blocked: something")

    out = action.run_action("task", "analysis", "admin", store=FakeStore(), notifications_path=tmp_path / "n.jsonl")

    assert out.startswith("[SENTINEL]")
    assert _read_jsonl(_isolated_audit_log) == []


def test_run_action_requires_write_role_before_calling_llm(monkeypatch):
    def boom(**_):
        raise AssertionError("LLM must not be called for a read-only role")

    monkeypatch.setattr(action, "call_llm", boom)
    with pytest.raises(PermissionError):
        action.run_action("task", "analysis", "readonly", store=FakeStore())


def test_admin_role_can_access_findings_namespace():
    from rbac import can_access_namespace
    assert can_access_namespace("admin", FINDINGS_NAMESPACE)
    assert not can_access_namespace("analyst", FINDINGS_NAMESPACE)


def test_deeply_nested_json_is_rejected_not_crashing():
    raw = '{"tool": "notify", "args": ' + "[" * 100_000 + "]" * 100_000 + "}"
    with pytest.raises(ToolCallRejected):
        parse_tool_call(raw)


def test_findings_are_marked_as_untrusted_llm_output(tmp_path):
    store = FakeStore()
    call = parse_tool_call('{"tool": "write_finding", "args": {"namespace": "findings", "text": "x"}}')

    execute_tool(call, "admin", store=store, notifications_path=tmp_path / "n.jsonl")

    assert store.upserts[0]["metadatas"][0]["trust"] == "untrusted_llm_output"
