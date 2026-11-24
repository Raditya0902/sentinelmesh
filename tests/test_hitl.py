"""Human-in-the-loop: HUMAN_REVIEW pauses the graph; a decision resumes it."""

import pytest

import orchestrator.main as orch
from agents.base import HumanReviewRequired, _approved_review_id

REVIEW_MSG = "[LOBSTER TRAP] Request requires human review before processing."


@pytest.fixture
def fake_agents(monkeypatch):
    """Analysis is held for review unless replayed with the matching approval."""
    calls = {"analysis": [], "critic": 0, "action": 0}

    def analysis(task, extracted_data):
        approval = _approved_review_id.get()
        calls["analysis"].append(approval)
        if approval != "req-42":
            raise HumanReviewRequired(REVIEW_MSG, "req-42", "analysis-agent-v1")
        return "approved summary"

    def critic(task, agent_output, agent_name):
        calls["critic"] += 1
        return '{"approved": true, "concerns": []}'

    def action(task, analysis_result, role):
        calls["action"] += 1
        return '{"tool": "write_finding", "status": "ok"}'

    monkeypatch.setattr(orch, "run_extraction", lambda **_: "extracted")
    monkeypatch.setattr(orch, "run_analysis", analysis)
    monkeypatch.setattr(orch, "run_critic", critic)
    monkeypatch.setattr(orch, "run_action", action)
    return calls


def _start(role="analyst", namespace="legal"):
    return orch.run_pipeline(task="Summarize GDPR controls.", document="doc", role=role, namespace=namespace)


def test_human_review_pauses_run(fake_agents):
    result = _start()

    assert result["status"] == "pending_review"
    assert result["review_request_id"] == "req-42"
    assert result["thread_id"]
    assert result["blocked"] is True
    assert result["error"].startswith("[LOBSTER TRAP]")
    assert result["analysis_result"] == ""
    assert fake_agents["critic"] == 0, "nothing downstream runs while the review is pending"


def test_approve_resumes_and_replays_with_approval(fake_agents):
    paused = _start()

    result = orch.resume_pipeline(paused["thread_id"], "approve")

    assert result["status"] == "completed"
    assert result["blocked"] is False
    assert result["error"] == ""
    assert result["analysis_result"] == "approved summary"
    assert fake_agents["analysis"] == [None, "req-42"]
    assert fake_agents["critic"] == 1
    assert result["review_outcome"] == "approved"


def test_approve_as_admin_continues_to_action(fake_agents):
    paused = _start(role="admin", namespace="general")

    result = orch.resume_pipeline(paused["thread_id"], "approve")

    assert result["status"] == "completed"
    assert fake_agents["action"] == 1
    assert result["action_result"]


def test_reject_finalizes_as_blocked(fake_agents):
    paused = _start()

    result = orch.resume_pipeline(paused["thread_id"], "reject")

    assert result["status"] == "blocked"
    assert result["blocked"] is True
    assert "rejected" in result["error"].lower()
    assert "req-42" in result["error"]
    assert fake_agents["analysis"] == [None]
    assert fake_agents["critic"] == 0
    assert result["review_outcome"] == "rejected"


def test_resume_unknown_thread_raises(fake_agents):
    with pytest.raises(orch.ReviewNotPending):
        orch.resume_pipeline("no-such-thread", "approve")


def test_resume_twice_raises(fake_agents):
    paused = _start()
    orch.resume_pipeline(paused["thread_id"], "reject")

    with pytest.raises(orch.ReviewNotPending):
        orch.resume_pipeline(paused["thread_id"], "approve")


def test_invalid_decision_rejected(fake_agents):
    paused = _start()
    with pytest.raises(ValueError):
        orch.resume_pipeline(paused["thread_id"], "maybe")


def test_completed_run_reports_completed(monkeypatch):
    monkeypatch.setattr(orch, "run_extraction", lambda **_: "extracted")
    monkeypatch.setattr(orch, "run_analysis", lambda **_: "summary")
    monkeypatch.setattr(orch, "run_critic", lambda **_: "ok")

    result = _start(role="analyst", namespace="general")

    assert result["status"] == "completed"
    assert result["review_request_id"] == ""
    assert result["analysis_result"] == "summary"


def test_critic_block_is_detected(monkeypatch):
    monkeypatch.setattr(orch, "run_extraction", lambda **_: "extracted")
    monkeypatch.setattr(orch, "run_analysis", lambda **_: "summary")
    monkeypatch.setattr(orch, "run_critic", lambda **_: "[SENTINEL] Output blocked: contains PII.")

    result = _start(role="admin", namespace="general")

    assert result["status"] == "blocked"
    assert result["error"].startswith("[SENTINEL]")
    assert result["action_result"] == ""


def test_action_tool_rejection_blocks_run(monkeypatch):
    from agents.action_tools import ToolCallRejected

    def rejected(**_):
        raise ToolCallRejected("unknown tool 'rm_rf'")

    monkeypatch.setattr(orch, "run_extraction", lambda **_: "extracted")
    monkeypatch.setattr(orch, "run_analysis", lambda **_: "summary")
    monkeypatch.setattr(orch, "run_critic", lambda **_: "ok")
    monkeypatch.setattr(orch, "run_action", rejected)

    result = _start(role="admin", namespace="general")

    assert result["blocked"] is True
    assert result["error"] == "action denied: unknown tool 'rm_rf'"


@pytest.fixture
def held_twice(monkeypatch):
    """Analysis is held (req-42); after approval, critic is held too (req-43)."""
    def analysis(task, extracted_data):
        if _approved_review_id.get() != "req-42":
            raise HumanReviewRequired(REVIEW_MSG, "req-42", "analysis-agent-v1")
        return "approved summary"

    def critic(task, agent_output, agent_name):
        if _approved_review_id.get() != "req-43":
            raise HumanReviewRequired(REVIEW_MSG, "req-43", "critic-agent-v1")
        return "ok"

    monkeypatch.setattr(orch, "run_extraction", lambda **_: "extracted")
    monkeypatch.setattr(orch, "run_analysis", analysis)
    monkeypatch.setattr(orch, "run_critic", critic)


def test_rehold_after_approval_pauses_again(held_twice):
    paused = _start()
    second = orch.resume_pipeline(paused["thread_id"], "approve")

    assert second["status"] == "pending_review"
    assert second["review_request_id"] == "req-43"
    assert orch.resume_pipeline(second["thread_id"], "approve")["status"] == "completed"


def test_reject_after_rehold_does_not_route_back_to_step(held_twice, monkeypatch):
    paused = _start()
    orch.resume_pipeline(paused["thread_id"], "approve")
    visited = []
    original = orch.route_after_review
    monkeypatch.setattr(orch, "route_after_review", lambda s: visited.append(s) or original(s))

    result = orch.resume_pipeline(paused["thread_id"], "reject")

    assert result["status"] == "blocked"
    assert result["approved_review"] is None


def test_failed_run_discards_checkpoint(monkeypatch):
    def boom(**_):
        raise RuntimeError("audit disk full")

    monkeypatch.setattr(orch, "_write_audit_denial", lambda *a, **k: boom())
    before = orch.paused_thread_count()
    with pytest.raises(RuntimeError):
        orch.run_pipeline(task="t", document="", role="readonly", namespace="hr")

    assert orch.paused_thread_count() == before


def test_discard_thread_removes_paused_run(fake_agents):
    paused = _start()
    orch.discard_thread(paused["thread_id"])

    with pytest.raises(orch.ReviewNotPending):
        orch.resume_pipeline(paused["thread_id"], "approve")
