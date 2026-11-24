"""Paused runs and the review → thread map survive an API restart (SQLite)."""

import json

import pytest

import orchestrator.main as orch
from agents.base import HumanReviewRequired, _approved_review_id
from api.state import ReviewThreads
from audit.writer import append_unless_conflict

REVIEW_MSG = "[LOBSTER TRAP] Request requires human review before processing."


@pytest.fixture
def sqlite_pipeline(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_CHECKPOINT_DB", str(tmp_path / "checkpoints.sqlite"))
    orch.reset_pipeline()
    yield tmp_path / "checkpoints.sqlite"
    monkeypatch.undo()
    orch.reset_pipeline()


@pytest.fixture
def held_analysis(monkeypatch):
    def analysis(task, extracted_data):
        if _approved_review_id.get() != "req-9":
            raise HumanReviewRequired(REVIEW_MSG, "req-9", "analysis-agent-v1")
        return "approved summary"

    monkeypatch.setattr(orch, "run_extraction", lambda **_: "extracted")
    monkeypatch.setattr(orch, "run_analysis", analysis)
    monkeypatch.setattr(orch, "run_critic", lambda **_: "ok")


def test_paused_run_survives_restart(sqlite_pipeline, held_analysis):
    paused = orch.run_pipeline(task="t", document="d", role="analyst", namespace="legal")
    assert paused["status"] == "pending_review"

    orch.reset_pipeline()  # new process: fresh connection, no in-memory state

    result = orch.resume_pipeline(paused["thread_id"], "approve")
    assert result["status"] == "completed"
    assert result["analysis_result"] == "approved summary"
    assert sqlite_pipeline.exists()


def test_finished_run_checkpoint_is_deleted(sqlite_pipeline, held_analysis):
    paused = orch.run_pipeline(task="t", document="d", role="analyst", namespace="legal")
    before = orch.paused_thread_count()

    orch.resume_pipeline(paused["thread_id"], "reject")

    assert orch.paused_thread_count() == before - 1


def test_review_threads_persist_across_instances(tmp_path):
    db = tmp_path / "threads.sqlite"
    ReviewThreads(db_path=str(db)).register("req-1", "thread-1")

    reopened = ReviewThreads(db_path=str(db))

    assert reopened.is_resumable("req-1")
    assert reopened.has_paused()
    assert reopened.claim("req-1") == "thread-1"
    assert ReviewThreads(db_path=str(db)).claim("req-1") is None, "claim is single-use"


def test_review_threads_ttl_uses_wall_clock(tmp_path):
    now = [1_000.0]
    threads = ReviewThreads(db_path=str(tmp_path / "t.sqlite"), ttl_seconds=60, clock=lambda: now[0])
    threads.register("req-1", "thread-1")
    now[0] += 61

    assert threads.register("req-2", "thread-2") == ["thread-1"]
    assert not threads.is_resumable("req-1")


def test_append_unless_conflict_writes_when_no_conflict(tmp_path):
    path = tmp_path / "decisions.jsonl"

    conflict = append_unless_conflict(path, {"request_id": "r1"}, lambda rows: None)

    assert conflict is None
    assert json.loads(path.read_text())["request_id"] == "r1"


def test_append_unless_conflict_sees_existing_rows_under_lock(tmp_path):
    path = tmp_path / "decisions.jsonl"
    path.write_text(json.dumps({"request_id": "r1", "decision": "reject"}) + "\n" + "not json\n")

    def first_for_r1(rows):
        return next((r for r in rows if r.get("request_id") == "r1"), None)

    conflict = append_unless_conflict(path, {"request_id": "r1", "decision": "approve"}, first_for_r1)

    assert conflict == {"request_id": "r1", "decision": "reject"}
    assert len(path.read_text().splitlines()) == 2, "nothing appended on conflict"


def test_api_round_trip_with_shared_sqlite_file(sqlite_pipeline, held_analysis, _isolated_audit_log):
    """Production layout: checkpoints and the review map share one SQLite file."""
    from fastapi.testclient import TestClient

    from api.main import create_app

    admin, analyst = "admin-key-0123456789abcdef", "analyst-key-0123456789abcd"
    env = {
        "SENTINEL_CALLER_KEYS": json.dumps({admin: "admin", analyst: "analyst"}),
        "AUDIT_LOG_PATH": str(_isolated_audit_log),
        "SENTINEL_CHECKPOINT_DB": str(sqlite_pipeline),
    }
    _isolated_audit_log.write_text(json.dumps({
        "timestamp": "2026-11-23T10:00:00+00:00", "request_id": "req-9",
        "action": "HUMAN_REVIEW", "agent_id": "analysis-agent-v1",
    }) + "\n")
    run = TestClient(create_app(env)).post(
        "/run", json={"task": "t", "namespace": "legal"}, headers={"X-Sentinel-Key": analyst})
    assert run.json()["status"] == "pending_review"

    orch.reset_pipeline()  # API restart: new app, new connections, same file
    decided = TestClient(create_app(env)).post(
        "/review/req-9/decide", json={"decision": "approve"}, headers={"X-Sentinel-Key": admin})

    assert decided.status_code == 200
    assert decided.json()["resumed"] is True
    assert decided.json()["run"]["status"] == "completed"


def test_expired_rows_do_not_count_as_paused(tmp_path):
    """Rotation must not stay blocked by a run abandoned past its TTL."""
    now = [1_000.0]
    threads = ReviewThreads(db_path=str(tmp_path / "t.sqlite"), ttl_seconds=60, clock=lambda: now[0])
    threads.register("req-1", "thread-1")
    now[0] += 61

    assert not threads.has_paused()
    assert not threads.is_resumable("req-1")
    assert threads.claim("req-1") is None


def test_file_db_uses_wal(tmp_path):
    db = tmp_path / "t.sqlite"
    threads = ReviewThreads(db_path=str(db))
    mode = threads._conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode == "wal"


def test_checkpoint_file_is_owner_only(sqlite_pipeline, held_analysis):
    orch.run_pipeline(task="t", document="SSN 123-45-6789", role="analyst", namespace="legal")
    assert sqlite_pipeline.stat().st_mode & 0o077 == 0


def test_orphaned_checkpoints_are_discarded(sqlite_pipeline, held_analysis):
    kept = orch.run_pipeline(task="t", document="d", role="analyst", namespace="legal")
    orphan = orch.run_pipeline(task="t", document="d", role="analyst", namespace="legal")

    removed = orch.discard_orphaned_threads(keep={kept["thread_id"]})

    assert removed == [orphan["thread_id"]]
    assert orch.checkpointed_thread_ids() == {kept["thread_id"]}


def test_startup_sweep_keeps_live_paused_runs(sqlite_pipeline, held_analysis, _isolated_audit_log):
    from fastapi.testclient import TestClient

    from api.main import create_app

    env = {"SENTINEL_CALLER_KEYS": json.dumps({"analyst-key-0123456789abcd": "analyst"}),
           "AUDIT_LOG_PATH": str(_isolated_audit_log), "SENTINEL_CHECKPOINT_DB": str(sqlite_pipeline)}
    app = create_app(env)
    with TestClient(app) as client:
        paused = client.post("/run", json={"task": "t", "namespace": "legal"},
                             headers={"X-Sentinel-Key": "analyst-key-0123456789abcd"}).json()
    orphan = orch.run_pipeline(task="t", document="d", role="analyst", namespace="legal")

    with TestClient(create_app(env)):  # restart: startup sweep runs
        pass

    assert orch.checkpointed_thread_ids() == {paused["thread_id"]}
    assert orphan["thread_id"] not in orch.checkpointed_thread_ids()


def test_checkpointer_uses_strict_serializer(sqlite_pipeline):
    serde = orch._pipeline().checkpointer.serde
    assert serde.pickle_fallback is False
    assert serde._allowed_msgpack_modules is None, "only built-in safe msgpack types"
