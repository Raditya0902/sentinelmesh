"""API human-in-the-loop: /run pauses on HUMAN_REVIEW, /review/{id}/decide resumes."""

import json

import pytest
from fastapi.testclient import TestClient

import orchestrator.main as orch
from agents.base import HumanReviewRequired, _approved_review_id

ADMIN_KEY = "admin-key-0123456789abcdef"
ANALYST_KEY = "analyst-key-0123456789abcd"
REVIEW_ID = "req-42"
REVIEW_MSG = "[LOBSTER TRAP] Request requires human review before processing."


@pytest.fixture
def audit_log(_isolated_audit_log):
    return _isolated_audit_log


@pytest.fixture
def client(audit_log, make_app):
    env = {
        "SENTINEL_CALLER_KEYS": json.dumps({ADMIN_KEY: "admin", ANALYST_KEY: "analyst"}),
        "AUDIT_LOG_PATH": str(audit_log),
    }
    return TestClient(make_app(env))


def _proxy_wrote_human_review(audit_log, request_id=REVIEW_ID):
    """What Lobster Trap appends when it holds a request."""
    with audit_log.open("a") as fh:
        fh.write(json.dumps({
            "timestamp": "2026-11-23T10:00:00+00:00", "request_id": request_id,
            "direction": "ingress", "action": "HUMAN_REVIEW",
            "rule_name": "human_review_mismatch", "agent_id": "analysis-agent-v1",
            "risk_score": 0.4,
        }) + "\n")


@pytest.fixture
def held_analysis(monkeypatch, audit_log):
    """Analysis is held until replayed with the approval; records what it saw."""
    seen = {"approvals": [], "decision_on_disk_at_replay": None}

    def analysis(task, extracted_data):
        approval = _approved_review_id.get()
        seen["approvals"].append(approval)
        if approval != REVIEW_ID:
            _proxy_wrote_human_review(audit_log)
            raise HumanReviewRequired(REVIEW_MSG, REVIEW_ID, "analysis-agent-v1")
        decisions = audit_log.parent / "review_decisions.jsonl"
        seen["decision_on_disk_at_replay"] = decisions.read_text() if decisions.exists() else ""
        return "approved summary"

    monkeypatch.setattr(orch, "run_extraction", lambda **_: "extracted")
    monkeypatch.setattr(orch, "run_analysis", analysis)
    monkeypatch.setattr(orch, "run_critic", lambda **_: "ok")
    return seen


def _run(client):
    return client.post("/run", json={"task": "Summarize GDPR controls.", "namespace": "legal"},
                       headers={"X-Sentinel-Key": ANALYST_KEY})


def _decide(client, decision, request_id=REVIEW_ID):
    return client.post(f"/review/{request_id}/decide", json={"decision": decision, "note": "ok"},
                       headers={"X-Sentinel-Key": ADMIN_KEY})


def test_run_returns_pending_review_with_thread(client, held_analysis):
    body = _run(client).json()

    assert body["status"] == "pending_review"
    assert body["review_request_id"] == REVIEW_ID
    assert body["thread_id"]
    assert body["blocked"] is True


def test_pending_item_shows_resumable_in_queue(client, held_analysis):
    _run(client)
    queue = client.get("/review/queue", headers={"X-Sentinel-Key": ADMIN_KEY}).json()

    assert [i["request_id"] for i in queue] == [REVIEW_ID]
    assert queue[0]["resumable"] is True


def test_approve_resumes_run_after_recording_decision(client, held_analysis):
    _run(client)

    resp = _decide(client, "approve")

    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "approve"
    assert body["resumed"] is True
    assert body["run"]["status"] == "completed"
    assert body["run"]["analysis_result"] == "approved summary"
    assert held_analysis["approvals"] == [None, REVIEW_ID]
    # The proxy verifies the approval from this file, so it must exist before replay.
    assert '"decision": "approve"' in held_analysis["decision_on_disk_at_replay"]


def test_reject_finalizes_run_as_blocked(client, held_analysis):
    _run(client)

    body = _decide(client, "reject").json()

    assert body["resumed"] is True
    assert body["run"]["status"] == "blocked"
    assert "Rejected" in body["run"]["error"]
    assert held_analysis["approvals"] == [None]


def test_second_decision_conflicts(client, held_analysis):
    _run(client)
    _decide(client, "approve")

    assert _decide(client, "reject").status_code == 409


def test_decision_without_paused_run_is_bookkeeping_only(client, audit_log):
    # e.g. the API restarted and the paused run was lost
    _proxy_wrote_human_review(audit_log, "req-7")

    body = _decide(client, "approve", request_id="req-7").json()

    assert body["decision"] == "approve"
    assert body["resumed"] is False
    assert body["run"] is None


def test_completed_run_reports_completed(client, monkeypatch):
    monkeypatch.setattr(orch, "run_extraction", lambda **_: "extracted")
    monkeypatch.setattr(orch, "run_analysis", lambda **_: "summary")
    monkeypatch.setattr(orch, "run_critic", lambda **_: "ok")

    body = client.post("/run", json={"task": "t", "namespace": "general"},
                       headers={"X-Sentinel-Key": ANALYST_KEY}).json()

    assert body["status"] == "completed"
    assert body["review_request_id"] == ""


def test_spoofed_role_field_is_rejected_and_audited(client, audit_log):
    resp = client.post("/run", json={"task": "t", "namespace": "hr", "role": "admin"},
                       headers={"X-Sentinel-Key": ANALYST_KEY})

    assert resp.status_code == 422
    entries = [json.loads(line) for line in audit_log.read_text().splitlines()]
    [entry] = [e for e in entries if e["rule_name"] == "auth_role_spoof_attempt"]
    assert entry["action"] == "DENY"
    assert entry["role"] == "analyst"
    assert entry["claimed_role"] == "admin"
    assert ANALYST_KEY not in json.dumps(entry)


@pytest.fixture
def held_twice(monkeypatch, audit_log):
    def analysis(task, extracted_data):
        if _approved_review_id.get() != REVIEW_ID:
            _proxy_wrote_human_review(audit_log)
            raise HumanReviewRequired(REVIEW_MSG, REVIEW_ID, "analysis-agent-v1")
        return "approved summary"

    def critic(task, agent_output, agent_name):
        if _approved_review_id.get() != "req-43":
            _proxy_wrote_human_review(audit_log, "req-43")
            raise HumanReviewRequired(REVIEW_MSG, "req-43", "critic-agent-v1")
        return "ok"

    monkeypatch.setattr(orch, "run_extraction", lambda **_: "extracted")
    monkeypatch.setattr(orch, "run_analysis", analysis)
    monkeypatch.setattr(orch, "run_critic", critic)


def test_second_hold_in_same_run_is_resumable(client, held_twice):
    _run(client)
    first = _decide(client, "approve").json()
    assert first["run"]["status"] == "pending_review"
    assert first["run"]["review_request_id"] == "req-43"

    second = _decide(client, "approve", request_id="req-43").json()

    assert second["resumed"] is True
    assert second["run"]["status"] == "completed"


def test_rotate_refused_while_runs_are_paused(client, held_analysis):
    _run(client)

    resp = client.post("/audit/rotate", headers={"X-Sentinel-Key": ADMIN_KEY})

    assert resp.status_code == 409


def test_unknown_queue_status_is_rejected(client):
    resp = client.get("/review/queue?status=bogus", headers={"X-Sentinel-Key": ADMIN_KEY})
    assert resp.status_code == 422


def test_overlong_note_is_rejected(client, held_analysis):
    _run(client)
    resp = client.post(f"/review/{REVIEW_ID}/decide", json={"decision": "approve", "note": "x" * 5000},
                       headers={"X-Sentinel-Key": ADMIN_KEY})
    assert resp.status_code == 422


def test_malformed_timestamp_does_not_break_queue(client, audit_log):
    with audit_log.open("a") as fh:
        fh.write(json.dumps({"timestamp": "not-a-time", "request_id": "req-9",
                             "action": "HUMAN_REVIEW", "rule_name": "r"}) + "\n")
    (audit_log.parent / "review_decisions.jsonl").write_text(json.dumps(
        {"request_id": "req-9", "decision": "approve", "decided_at": "also-bad"}) + "\n")

    resp = client.get("/review/queue?status=all", headers={"X-Sentinel-Key": ADMIN_KEY})

    assert resp.status_code == 200


def test_expired_paused_runs_are_discarded():
    from api.state import ReviewThreads

    now = [1000.0]
    with ReviewThreads(ttl_seconds=60, clock=lambda: now[0]) as threads:
        threads.register("req-1", "thread-1")
        now[0] += 61

        expired = threads.register("req-2", "thread-2")

        assert expired == ["thread-1"]
        assert not threads.is_resumable("req-1")
        assert threads.is_resumable("req-2")


def test_first_decision_wins_in_queue(client, audit_log):
    _proxy_wrote_human_review(audit_log, "req-8")
    (audit_log.parent / "review_decisions.jsonl").write_text(
        json.dumps({"request_id": "req-8", "decision": "reject", "decided_at": "2026-11-23T10:01:00+00:00"}) + "\n"
        + json.dumps({"request_id": "req-8", "decision": "approve", "decided_at": "2026-11-23T10:02:00+00:00"}) + "\n")

    queue = client.get("/review/queue?status=all", headers={"X-Sentinel-Key": ADMIN_KEY}).json()

    assert [i["decision"] for i in queue if i["request_id"] == "req-8"] == ["reject"]
