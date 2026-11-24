"""api/main.py: root, /run failure path, /audit limits and malformed lines, shutdown."""

import json

import pytest
from fastapi.testclient import TestClient

from api.main import create_app

ADMIN_KEY = "admin-key-0123456789abcdef"
ANALYST_KEY = "analyst-key-0123456789abcd"


@pytest.fixture
def client(_isolated_audit_log):
    env = {
        "SENTINEL_CALLER_KEYS": json.dumps({ADMIN_KEY: "admin", ANALYST_KEY: "analyst"}),
        "AUDIT_LOG_PATH": str(_isolated_audit_log),
    }
    return TestClient(create_app(env))


def test_root_points_at_docs(client):
    assert client.get("/").json()["docs"] == "/docs"


def test_run_crash_returns_generic_500(client, monkeypatch):
    def crash(**_):
        raise RuntimeError("db password=hunter2")

    monkeypatch.setattr("orchestrator.main.run_pipeline", crash)

    resp = client.post("/run", json={"task": "t"}, headers={"X-Sentinel-Key": ANALYST_KEY})

    assert resp.status_code == 500
    assert resp.json() == {"detail": "Pipeline execution failed"}


def test_audit_missing_file_returns_empty(client):
    assert client.get("/audit", headers={"X-Sentinel-Key": ADMIN_KEY}).json() == []


def test_audit_skips_malformed_lines_and_tails(client, _isolated_audit_log):
    lines = [json.dumps({"n": i}) for i in range(5)] + ["{not json"]
    _isolated_audit_log.write_text("\n".join(lines) + "\n")

    resp = client.get("/audit?limit=3", headers={"X-Sentinel-Key": ADMIN_KEY})

    assert resp.json() == [{"n": 3}, {"n": 4}]


@pytest.mark.parametrize("limit", [0, 1001])
def test_audit_limit_is_bounded(client, limit):
    resp = client.get(f"/audit?limit={limit}", headers={"X-Sentinel-Key": ADMIN_KEY})
    assert resp.status_code == 422


def test_analyst_cannot_read_audit(client):
    assert client.get("/audit", headers={"X-Sentinel-Key": ANALYST_KEY}).status_code == 403


def test_create_app_from_process_env(monkeypatch, _isolated_audit_log):
    monkeypatch.setattr("api.main.load_env_file", lambda: False)
    monkeypatch.setenv("SENTINEL_CALLER_KEYS", json.dumps({ADMIN_KEY: "admin"}))

    app = create_app()

    assert app.state.settings.audit_log_path == _isolated_audit_log


def test_shutdown_closes_review_db(client):
    with client:  # runs lifespan startup + shutdown
        assert client.get("/health").status_code == 200
    assert client.app.state.review_threads.closed
