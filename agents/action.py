"""Action agent: turns confirmed analysis into exactly one scoped, audited tool call."""

from __future__ import annotations

import itertools
import threading
import time
from pathlib import Path
from typing import Optional

from audit.writer import append_entry
from rbac import assert_write_access

from .action_tools import (
    DEFAULT_NOTIFICATIONS_PATH,
    FINDINGS_NAMESPACE,
    ToolCallRejected,
    VectorWriter,
    execute_tool,
    parse_tool_call,
)
from .base import call_llm, is_sentinel_blocked

AGENT_ID = "action-agent-v1"

SYSTEM_PROMPT = f"""You are an action agent. Based on the confirmed analysis, choose exactly
ONE tool call and reply with a single JSON object and nothing else.

Tools:
  {{"tool": "write_finding", "args": {{"namespace": "{FINDINGS_NAMESPACE}", "text": "<finding, max 4000 chars>"}}}}
  {{"tool": "notify", "args": {{"channel": "<lowercase-channel>", "message": "<max 1000 chars>"}}}}

Prefer write_finding to record the analysis outcome. The only writable namespace is
"{FINDINGS_NAMESPACE}". Any other tool or namespace will be rejected and audited."""

_seq = itertools.count(1)
_seq_lock = threading.Lock()


def _audit_tool(rule_name: str, action: str, role: str, tool: str, detail: str) -> None:
    with _seq_lock:
        seq = next(_seq)
    entry = {
        "request_id": f"action-{int(time.time() * 1000)}-{seq}",
        "direction": "tool",
        "action": action,
        "rule_name": rule_name,
        "agent_id": AGENT_ID,
        "role": role,
        "tool": tool,
    }
    key = "deny_message" if action == "DENY" else "detail"
    append_entry({**entry, key: detail})


def _default_store() -> VectorWriter:
    from rbac.vector_store import NamespacedVectorStore

    return NamespacedVectorStore()


def run_action(
    task: str,
    analysis_result: str,
    role: str,
    *,
    store: Optional[VectorWriter] = None,
    notifications_path: Path = DEFAULT_NOTIFICATIONS_PATH,
) -> str:
    """Ask the LLM for one tool call, validate it, execute it, and audit the outcome.

    Raises PermissionError for read-only roles (before any LLM call) and
    ToolCallRejected (after auditing) when the proposed call is not allowed.
    """
    assert_write_access(role)
    raw = call_llm(
        agent_id=AGENT_ID,
        system=SYSTEM_PROMPT,
        user=f"Task: {task}\n\nAnalysis:\n{analysis_result}",
        declared_intent="code_execution",
        response_format={"type": "json_object"},
    )
    if is_sentinel_blocked(raw):
        return raw

    proposed = "unparsed"
    try:
        call = parse_tool_call(raw)
        proposed = call.tool
        result = execute_tool(call, role, store=store or _default_store(),
                              notifications_path=notifications_path)
    except ToolCallRejected as exc:
        _audit_tool("action_tool_denied", "DENY", role, proposed, str(exc))
        raise
    _audit_tool("action_tool_executed", "ALLOW", role, result.tool, result.to_json())
    return result.to_json()
