"""
SentinelMesh LangGraph pipeline.

Flow: orchestrator → extraction → analysis → (action if write role) → critic → END
Every LLM call routes through Lobster Trap at LOBSTER_TRAP_URL.
"""

from __future__ import annotations

# load_dotenv must run before any agent module is imported so env vars are
# available when agents/base.py reads them for the first time.
from dotenv import load_dotenv

load_dotenv()

import json
from typing import Literal, TypedDict

from langgraph.graph import END, StateGraph

from agents import run_action, run_analysis, run_critic, run_extraction
from rbac import can_access_namespace, get_role


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


def _initial_state(task: str, document: str, role: str, namespace: str) -> AgentState:
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
    )


# ── nodes ──────────────────────────────────────────────────────────────────────

def orchestrator_node(state: AgentState) -> AgentState:
    """Validates RBAC before the pipeline proceeds."""
    try:
        get_role(state["role"])
    except ValueError as exc:
        return {**state, "blocked": True, "error": str(exc)}

    if not can_access_namespace(state["role"], state["namespace"]):
        msg = (
            f"Role {state['role']!r} cannot access namespace {state['namespace']!r}. "
            "Access denied."
        )
        return {**state, "blocked": True, "error": msg}

    return state


def _sentinel_blocked(text: str) -> bool:
    return text.strip().startswith("[SENTINEL]")


def extraction_node(state: AgentState) -> AgentState:
    if state["blocked"]:
        return state
    result = run_extraction(
        task=state["task"],
        document=state["document"],
        role=state["role"],
        namespace=state["namespace"],
    )
    if _sentinel_blocked(result):
        return {**state, "extracted_data": result, "blocked": True, "error": result}
    return {**state, "extracted_data": result}


def analysis_node(state: AgentState) -> AgentState:
    if state["blocked"]:
        return state
    result = run_analysis(task=state["task"], extracted_data=state["extracted_data"])
    if _sentinel_blocked(result):
        return {**state, "analysis_result": result, "blocked": True, "error": result}
    return {**state, "analysis_result": result}


def critic_node(state: AgentState) -> AgentState:
    if state["blocked"]:
        return state
    review = run_critic(
        task=state["task"],
        agent_output=state["analysis_result"],
        agent_name="analysis-agent",
    )
    return {**state, "critic_reviews": [*state["critic_reviews"], review]}


def action_node(state: AgentState) -> AgentState:
    if state["blocked"]:
        return state
    try:
        result = run_action(
            task=state["task"],
            analysis_result=state["analysis_result"],
            role=state["role"],
        )
        return {**state, "action_result": result}
    except PermissionError as exc:
        return {**state, "blocked": True, "error": str(exc)}


# ── routing ────────────────────────────────────────────────────────────────────

def route_after_orchestrator(
    state: AgentState,
) -> Literal["extraction_node", "__end__"]:
    if state["blocked"]:
        return END
    return "extraction_node"


def route_after_critic(state: AgentState) -> Literal["action_node", "__end__"]:
    role = get_role(state["role"])
    if role.can_write and not state["blocked"]:
        return "action_node"
    return END


# ── graph ──────────────────────────────────────────────────────────────────────

def build_pipeline() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("orchestrator_node", orchestrator_node)
    graph.add_node("extraction_node", extraction_node)
    graph.add_node("analysis_node", analysis_node)
    graph.add_node("critic_node", critic_node)
    graph.add_node("action_node", action_node)

    graph.set_entry_point("orchestrator_node")

    graph.add_conditional_edges(
        "orchestrator_node",
        route_after_orchestrator,
        {"extraction_node": "extraction_node", END: END},
    )
    graph.add_edge("extraction_node", "analysis_node")
    graph.add_edge("analysis_node", "critic_node")
    graph.add_conditional_edges(
        "critic_node",
        route_after_critic,
        {"action_node": "action_node", END: END},
    )
    graph.add_edge("action_node", END)

    return graph


def run_pipeline(task: str, document: str, role: str, namespace: str = "general") -> AgentState:
    pipeline = build_pipeline().compile()
    initial = _initial_state(task=task, document=document, role=role, namespace=namespace)
    return pipeline.invoke(initial)


if __name__ == "__main__":
    result = run_pipeline(
        task="Summarize the document and flag any compliance risks.",
        document="Patient SSN: 123-45-6789. Diagnosis: hypertension. Prescribed: lisinopril.",
        role="analyst",
        namespace="general",
    )
    print(json.dumps(result, indent=2))
