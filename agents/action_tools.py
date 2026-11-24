"""The action agent's tools: a closed set, validated before anything executes.

The LLM proposes exactly one tool call as JSON ``{"tool": ..., "args": {...}}``. It is
parsed with Pydantic (unknown tools, unknown fields, and out-of-range values are
rejected), then executed with the caller's server-side role, re-checking RBAC.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal, Optional, Protocol, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from audit.writer import append_entry, utc_now_iso
from rbac.roles import can_access_namespace, get_role

FINDINGS_NAMESPACE = "findings"
# The action agent may only write here, whatever namespaces its role can reach.
ACTION_WRITABLE_NAMESPACES = frozenset({FINDINGS_NAMESPACE})
DEFAULT_NOTIFICATIONS_PATH = Path("logs/notifications.jsonl")
MAX_FINDING_CHARS = 4000
MAX_MESSAGE_CHARS = 1000
TOOL_NAMES = ("write_finding", "notify")

_CODE_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)


class ToolCallRejected(Exception):
    """The proposed tool call was not executed."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WriteFindingArgs(_Strict):
    namespace: str = Field(pattern=r"^[a-z0-9_-]{1,32}$")
    text: str = Field(min_length=1, max_length=MAX_FINDING_CHARS)


class NotifyArgs(_Strict):
    channel: str = Field(pattern=r"^[a-z0-9-]{1,32}$")
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)


class WriteFindingCall(_Strict):
    tool: Literal["write_finding"]
    args: WriteFindingArgs


class NotifyCall(_Strict):
    tool: Literal["notify"]
    args: NotifyArgs


ToolCall = Annotated[Union[WriteFindingCall, NotifyCall], Field(discriminator="tool")]
_TOOL_CALL = TypeAdapter(ToolCall)


@dataclass(frozen=True)
class ToolResult:
    tool: str
    status: str
    detail: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({"tool": self.tool, "status": self.status, **self.detail})


class VectorWriter(Protocol):
    def upsert(
        self,
        role_name: str,
        namespace: str,
        documents: list[str],
        ids: list[str],
        metadatas: Optional[list[dict]] = None,
    ) -> None: ...


def _load_json_object(raw: str) -> dict:
    text = raw.strip()
    fenced = _CODE_FENCE.match(text)
    if fenced:
        text = fenced.group(1)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ToolCallRejected(f"tool call is not valid JSON ({exc.msg})") from exc
    except RecursionError as exc:
        raise ToolCallRejected("tool call is not valid JSON (nested too deeply)") from exc
    if not isinstance(payload, dict):
        raise ToolCallRejected("tool call must be a JSON object")
    return payload


def parse_tool_call(raw: str) -> ToolCall:
    """Validate an LLM-proposed tool call. Raises ToolCallRejected on anything else."""
    payload = _load_json_object(raw)
    tool = payload.get("tool")
    if tool not in TOOL_NAMES:
        raise ToolCallRejected(f"unknown tool {tool!r}; allowed: {list(TOOL_NAMES)}")
    try:
        return _TOOL_CALL.validate_python(payload)
    except ValidationError as exc:
        fields = ", ".join(".".join(map(str, e["loc"])) for e in exc.errors())
        raise ToolCallRejected(f"invalid arguments for {tool!r}: {fields}") from exc


def _write_finding(call: WriteFindingCall, role: str, store: VectorWriter) -> ToolResult:
    namespace = call.args.namespace
    if namespace not in ACTION_WRITABLE_NAMESPACES:
        raise ToolCallRejected(
            f"namespace {namespace!r} is not writable by the action agent; "
            f"allowed: {sorted(ACTION_WRITABLE_NAMESPACES)}"
        )
    if not get_role(role).can_write or not can_access_namespace(role, namespace):
        raise ToolCallRejected(f"role {role!r} may not write to namespace {namespace!r}")
    finding_id = f"finding-{uuid.uuid4().hex}"
    store.upsert(
        role,
        namespace,
        documents=[call.args.text],
        ids=[finding_id],
        # Findings are LLM output derived from untrusted documents: anything that
        # retrieves them must treat them as data, never as instructions.
        metadatas=[{"source": "action-agent-v1", "role": role, "created_at": utc_now_iso(),
                    "trust": "untrusted_llm_output"}],
    )
    return ToolResult("write_finding", "ok", {"namespace": namespace, "id": finding_id})


def _notify(call: NotifyCall, role: str, notifications_path: Path) -> ToolResult:
    append_entry(
        {"channel": call.args.channel, "message": call.args.message, "role": role,
         "agent_id": "action-agent-v1"},
        path=notifications_path,
        strict=True,
    )
    return ToolResult("notify", "ok", {"channel": call.args.channel})


def execute_tool(
    call: ToolCall,
    role: str,
    *,
    store: VectorWriter,
    notifications_path: Path = DEFAULT_NOTIFICATIONS_PATH,
) -> ToolResult:
    if isinstance(call, WriteFindingCall):
        return _write_finding(call, role, store)
    return _notify(call, role, notifications_path)
