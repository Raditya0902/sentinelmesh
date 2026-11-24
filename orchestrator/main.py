"""
SentinelMesh LangGraph pipeline.

Flow: orchestrator → extraction → analysis → critic → (action if write role) → END

Every LLM call routes through Lobster Trap at LOBSTER_TRAP_URL. When the proxy holds a
call for HUMAN_REVIEW, the step records a pending review and the graph pauses in
``human_review_node`` (LangGraph ``interrupt``). ``resume_pipeline`` continues it:
approve replays the held step with the approval reference the proxy verifies; reject
ends the run as blocked.
"""

from __future__ import annotations

# load_dotenv must run before any agent module is imported so env vars are
# available when agents/base.py reads them for the first time.
from dotenv import load_dotenv

load_dotenv()

import itertools
import json
import threading
import time as _time
import uuid
from collections.abc import Callable
from typing import Literal, Optional, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.types import Command, interrupt

from agents import run_action, run_analysis, run_critic, run_extraction
from agents.action_tools import ToolCallRejected
from agents.base import HumanReviewRequired, is_sentinel_blocked, review_approval
from audit.writer import append_entry
from rbac import can_access_namespace, get_role

DECISIONS = ("approve", "reject")

_audit_counter = itertools.count(1)
_audit_lock = threading.Lock()


class ReviewNotPending(LookupError):
    """No paused run exists for this thread (unknown, already decided, or lost on restart)."""


def _write_audit_denial(role: str, namespace: str, rule_name: str, deny_message: str) -> None:
    """Record an RBAC denial. Raises AuditWriteError in strict mode if it can't be persisted."""
    with _audit_lock:
        seq = next(_audit_counter)
    append_entry({
        "request_id": f"rbac-{int(_time.time() * 1000)}-{seq}",
        "direction": "ingress",
        "action": "DENY",
        "rule_name": rule_name,
        "deny_message": deny_message,
        "agent_id": "orchestrator",
        "role": role,
        "namespace": namespace,
    })


class PendingReview(TypedDict):
    request_id: str
    step: str
    agent_id: str


class AgentState(TypedDict):
    task: str
    document: str
    role: str
    namespace: str
    extracted_data: str
    analysis_result: str
    action_result: str
    critic_reviews: list[str]
    blocked: bool
    error: str
    thread_id: str
    pending_review: Optional[PendingReview]
    approved_review: Optional[PendingReview]
    review_outcome: str


def _initial_state(task: str, document: str, role: str, namespace: str, thread_id: str) -> AgentState:
    return AgentState(
        task=task,
        document=document,
        role=role,
        namespace=namespace,
        extracted_data="",
        analysis_result="",
        action_result="",
        critic_reviews=[],
        blocked=False,
        error="",
        thread_id=thread_id,
        pending_review=None,
        approved_review=None,
        review_outcome="",
    )


# Kept for existing callers/tests; the canonical helper lives in agents.base.
_sentinel_blocked = is_sentinel_blocked


# ── nodes ──────────────────────────────────────────────────────────────────────

def orchestrator_node(state: AgentState) -> AgentState:
    """Validates RBAC before the pipeline proceeds."""
    try:
        get_role(state["role"])
    except ValueError as exc:
        msg = str(exc)
        _write_audit_denial(state["role"], state["namespace"], "rbac_invalid_role", msg)
        return {**state, "blocked": True, "error": msg}

    if not can_access_namespace(state["role"], state["namespace"]):
        msg = (
            f"Role {state['role']!r} cannot access namespace {state['namespace']!r}. "
            "Access denied."
        )
        _write_audit_denial(state["role"], state["namespace"], "rbac_namespace_denied", msg)
        return {**state, "blocked": True, "error": msg}

    return state


def _approval_for(state: AgentState, step: str) -> Optional[str]:
    approved = state.get("approved_review")
    return approved["request_id"] if approved and approved["step"] == step else None


class StepDenied(Exception):
    """A step refused to proceed; the message becomes the run's error verbatim."""


Apply = Callable[[AgentState, str], AgentState]


def _run_llm_step(
    state: AgentState,
    step: str,
    call: Callable[[AgentState], str],
    apply: Apply,
) -> AgentState:
    """Run one agent step; translate proxy blocks, review holds, and failures into state."""
    if state["blocked"]:
        return state
    try:
        with review_approval(_approval_for(state, step)):
            result = call(state)
    except HumanReviewRequired as held:
        pending = PendingReview(request_id=held.request_id, step=step, agent_id=held.agent_id)
        return {**state, "blocked": True, "error": str(held), "pending_review": pending}
    except StepDenied as denied:
        return {**state, "blocked": True, "error": str(denied)}
    except Exception as exc:
        return {**state, "blocked": True, "error": f"{step} failed: {exc}"}
    cleared: AgentState = {**state, "approved_review": None}
    if is_sentinel_blocked(result):
        return {**cleared, "blocked": True, "error": result}
    return apply(cleared, result)


def _set(field: str) -> Apply:
    return lambda state, result: {**state, field: result}


def extraction_node(state: AgentState) -> AgentState:
    return _run_llm_step(state, "extraction", lambda s: run_extraction(
        task=s["task"], document=s["document"], role=s["role"], namespace=s["namespace"],
    ), _set("extracted_data"))


def analysis_node(state: AgentState) -> AgentState:
    return _run_llm_step(state, "analysis", lambda s: run_analysis(
        task=s["task"], extracted_data=s["extracted_data"],
    ), _set("analysis_result"))


def critic_node(state: AgentState) -> AgentState:
    return _run_llm_step(state, "critic", lambda s: run_critic(
        task=s["task"], agent_output=s["analysis_result"], agent_name="analysis-agent",
    ), lambda s, review: {**s, "critic_reviews": [*s["critic_reviews"], review]})


def _call_action(state: AgentState) -> str:
    try:
        return run_action(task=state["task"], analysis_result=state["analysis_result"],
                          role=state["role"])
    except ToolCallRejected as exc:  # already audited by the action agent
        raise StepDenied(f"action denied: {exc}") from exc


def action_node(state: AgentState) -> AgentState:
    if state["blocked"]:
        return state
    role = state["role"]
    if not get_role(role).can_write:  # role was validated by orchestrator_node
        msg = f"Role {role!r} does not have write access"
        _write_audit_denial(role, state["namespace"], "rbac_write_denied", msg)
        return {**state, "blocked": True, "error": msg}
    return _run_llm_step(state, "action", _call_action, _set("action_result"))


def human_review_node(state: AgentState) -> AgentState:
    """Pause until a human decides. Re-runs on resume, so it must stay side-effect free."""
    pending = state["pending_review"]
    resumed = interrupt({
        "request_id": pending["request_id"],
        "step": pending["step"],
        "agent_id": pending["agent_id"],
        "message": state["error"],
    })
    decision = resumed.get("decision") if isinstance(resumed, dict) else resumed
    if decision == "approve":
        return {**state, "blocked": False, "error": "", "pending_review": None,
                "approved_review": pending, "review_outcome": "approved"}
    return {**state, "pending_review": None, "approved_review": None, "review_outcome": "rejected",
            "error": f"[LOBSTER TRAP] Rejected by human reviewer (review {pending['request_id']})."}


# ── routing ────────────────────────────────────────────────────────────────────

def route_after_orchestrator(
    state: AgentState,
) -> Literal["extraction_node", "__end__"]:
    if state["blocked"]:
        return END
    return "extraction_node"


def route_after_critic(state: AgentState) -> Literal["action_node", "__end__"]:
    try:
        role = get_role(state["role"])
    except ValueError:
        return END
    if role.can_write and not state["blocked"]:
        return "action_node"
    return END


def _review_or(next_route: Callable[[AgentState], str]) -> Callable[[AgentState], str]:
    def route(state: AgentState) -> str:
        if state.get("pending_review"):
            return "human_review_node"
        return next_route(state)
    return route


def route_after_review(state: AgentState) -> str:
    approved = state.get("approved_review")
    if state.get("review_outcome") == "approved" and approved:
        return f"{approved['step']}_node"
    return END


# ── graph ──────────────────────────────────────────────────────────────────────

_STEP_NODES = ("extraction_node", "analysis_node", "critic_node", "action_node")


def build_pipeline() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("orchestrator_node", orchestrator_node)
    graph.add_node("extraction_node", extraction_node)
    graph.add_node("analysis_node", analysis_node)
    graph.add_node("critic_node", critic_node)
    graph.add_node("action_node", action_node)
    graph.add_node("human_review_node", human_review_node)

    graph.set_entry_point("orchestrator_node")

    graph.add_conditional_edges(
        "orchestrator_node",
        route_after_orchestrator,
        {"extraction_node": "extraction_node", END: END},
    )
    with_review = {"human_review_node": "human_review_node"}
    graph.add_conditional_edges("extraction_node", _review_or(lambda s: "analysis_node"),
                                {**with_review, "analysis_node": "analysis_node"})
    graph.add_conditional_edges("analysis_node", _review_or(lambda s: "critic_node"),
                                {**with_review, "critic_node": "critic_node"})
    graph.add_conditional_edges("critic_node", _review_or(route_after_critic),
                                {**with_review, "action_node": "action_node", END: END})
    graph.add_conditional_edges("action_node", _review_or(lambda s: END),
                                {**with_review, END: END})
    graph.add_conditional_edges("human_review_node", route_after_review,
                                {**{n: n for n in _STEP_NODES}, END: END})

    return graph


# Paused runs live in memory: they survive across requests but not an API restart.
_CHECKPOINTER = MemorySaver()
_PIPELINE = build_pipeline().compile(checkpointer=_CHECKPOINTER)


def _config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}}


def _finish(raw: dict, thread_id: str) -> dict:
    """Attach status fields; forget the checkpoint once the run is no longer paused."""
    state = {k: v for k, v in raw.items() if k != "__interrupt__"}
    pending = state.get("pending_review")
    if pending:
        status = "pending_review"
    else:
        status = "blocked" if state["blocked"] else "completed"
        discard_thread(thread_id)
    return {
        **state,
        "status": status,
        "thread_id": thread_id,
        "review_request_id": pending["request_id"] if pending else "",
    }


def discard_thread(thread_id: str) -> None:
    """Forget a run's checkpoint (finished, failed, or abandoned while paused)."""
    _CHECKPOINTER.delete_thread(thread_id)


def paused_thread_count() -> int:
    """Number of runs with a live checkpoint (diagnostics/tests)."""
    return len(_CHECKPOINTER.storage)


def _invoke(payload: object, thread_id: str) -> dict:
    try:
        raw = _PIPELINE.invoke(payload, _config(thread_id))
    except Exception:
        discard_thread(thread_id)  # a crashed run can never be resumed
        raise
    return _finish(raw, thread_id)


def run_pipeline(task: str, document: str, role: str, namespace: str = "general") -> dict:
    """Run the graph. Returns the final state plus status/thread_id/review_request_id."""
    thread_id = uuid.uuid4().hex
    initial = _initial_state(task=task, document=document, role=role,
                             namespace=namespace, thread_id=thread_id)
    return _invoke(initial, thread_id)


def resume_pipeline(thread_id: str, decision: str, note: str = "") -> dict:
    """Resume a run paused for human review with "approve" or "reject"."""
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {DECISIONS}, got {decision!r}")
    snapshot = _PIPELINE.get_state(_config(thread_id))
    if not snapshot.next or "human_review_node" not in snapshot.next:
        raise ReviewNotPending(f"no run is waiting for review on thread {thread_id!r}")
    return _invoke(Command(resume={"decision": decision, "note": note}), thread_id)


if __name__ == "__main__":
    result = run_pipeline(
        task="Summarize the document and flag any compliance risks.",
        document="Patient SSN: 123-45-6789. Diagnosis: hypertension. Prescribed: lisinopril.",
        role="analyst",
        namespace="general",
    )
    print(json.dumps(result, indent=2))
