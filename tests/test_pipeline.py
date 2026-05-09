import pytest
from orchestrator.main import (
    AgentState, 
    orchestrator_node, 
    _sentinel_blocked, 
    route_after_orchestrator, 
    route_after_critic
)
from langgraph.graph import END

def create_state(role="readonly", namespace="general", blocked=False) -> AgentState:
    return {
        "task": "test task",
        "document": "test doc",
        "role": role,
        "namespace": namespace,
        "extracted_data": "",
        "analysis_result": "",
        "action_result": "",
        "critic_reviews": [],
        "blocked": blocked,
        "error": "",
    }

def test_sentinel_blocked():
    assert _sentinel_blocked("[SENTINEL] Blocked") is True
    assert _sentinel_blocked("  [SENTINEL] Blocked  ") is True
    assert _sentinel_blocked("Normal output") is False
    assert _sentinel_blocked("") is False

def test_orchestrator_node_valid():
    state = create_state(role="admin", namespace="hr")
    next_state = orchestrator_node(state)
    assert next_state["blocked"] is False
    assert next_state["error"] == ""

def test_orchestrator_node_invalid_role():
    state = create_state(role="invalid_role", namespace="general")
    next_state = orchestrator_node(state)
    assert next_state["blocked"] is True
    assert "Unknown role" in next_state["error"]

def test_orchestrator_node_denied_namespace():
    state = create_state(role="readonly", namespace="hr")
    next_state = orchestrator_node(state)
    assert next_state["blocked"] is True
    assert "cannot access namespace" in next_state["error"]

def test_route_after_orchestrator():
    state_ok = create_state(blocked=False)
    assert route_after_orchestrator(state_ok) == "extraction_node"
    
    state_blocked = create_state(blocked=True)
    assert route_after_orchestrator(state_blocked) == END

def test_route_after_critic_admin():
    state = create_state(role="admin", blocked=False)
    assert route_after_critic(state) == "action_node"

def test_route_after_critic_readonly():
    state = create_state(role="readonly", blocked=False)
    assert route_after_critic(state) == END

def test_route_after_critic_blocked():
    state = create_state(role="admin", blocked=True)
    assert route_after_critic(state) == END
