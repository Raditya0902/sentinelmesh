import json

import pytest
from fastapi.testclient import TestClient

from api.auth import load_auth_config
from api.main import create_app

ADMIN_KEY = "admin-key-0123456789abcdef"
ANALYST_KEY = "analyst-key-0123456789abcd"
AUDITOR_KEY = "auditor-key-0123456789abcd"


@pytest.fixture
def audit_log(_isolated_audit_log):
    # Same path the orchestrator writes to via AUDIT_LOG_PATH (see conftest.py).
    return _isolated_audit_log


@pytest.fixture
def env(audit_log):
    return {
        "SENTINEL_CALLER_KEYS": json.dumps(
            {ADMIN_KEY: "admin", ANALYST_KEY: "analyst", AUDITOR_KEY: "auditor"}
        ),
        "AUDIT_LOG_PATH": str(audit_log),
    }


@pytest.fixture
def client(env):
    return TestClient(create_app(env))


@pytest.fixture
def captured_pipeline(monkeypatch):
    calls = []

    def fake_run_pipeline(task, document, role, namespace):
        calls.append({"role": role, "namespace": namespace})
        return {
            "task": task, "role": role, "namespace": namespace, "blocked": False,
            "error": "", "extracted_data": "", "analysis_result": "",
            "action_result": "", "critic_reviews": [],
        }

    monkeypatch.setattr("orchestrator.main.run_pipeline", fake_run_pipeline)
    return calls


def _audit_rules(audit_log):
    if not audit_log.exists():
        return []
    return [json.loads(line)["rule_name"] for line in audit_log.read_text().splitlines()]


# ── startup / config ───────────────────────────────────────────────────────────

def test_startup_fails_when_no_keys_configured(audit_log):
    with pytest.raises(RuntimeError, match="SENTINEL_CALLER_KEYS"):
        create_app({"AUDIT_LOG_PATH": str(audit_log)})


def test_startup_allowed_without_keys_in_explicit_demo_mode(audit_log):
    app = create_app({"SENTINEL_DEMO_MODE": "1", "AUDIT_LOG_PATH": str(audit_log)})
    assert TestClient(app).get("/health").status_code == 200


def test_config_rejects_unknown_role():
    with pytest.raises(ValueError, match="Unknown role"):
        load_auth_config({"SENTINEL_CALLER_KEYS": json.dumps({ADMIN_KEY: "superuser"})})


def test_config_rejects_short_keys():
    with pytest.raises(ValueError, match="at least"):
        load_auth_config({"SENTINEL_CALLER_KEYS": json.dumps({"short": "admin"})})


def test_config_rejects_malformed_json():
    with pytest.raises(ValueError, match="valid JSON"):
        load_auth_config({"SENTINEL_CALLER_KEYS": "{not json"})


def test_legacy_sentinel_api_key_maps_to_admin():
    config = load_auth_config({"SENTINEL_API_KEY": ADMIN_KEY})
    assert config.resolve_role(ADMIN_KEY) == "admin"


# ── /run ───────────────────────────────────────────────────────────────────────

def test_run_without_key_returns_401_and_is_audited(client, audit_log, captured_pipeline):
    resp = client.post("/run", json={"task": "hi"})

    assert resp.status_code == 401
    assert captured_pipeline == []
    assert _audit_rules(audit_log) == ["auth_missing_key"]


def test_run_with_unknown_key_returns_401_and_is_audited(client, audit_log, captured_pipeline):
    resp = client.post("/run", json={"task": "hi"}, headers={"X-Sentinel-Key": "nope" * 8})

    assert resp.status_code == 401
    assert _audit_rules(audit_log) == ["auth_invalid_key"]


def test_run_audit_entry_never_contains_the_presented_key(client, audit_log):
    bad_key = "attacker-supplied-key-123456"
    client.post("/run", json={"task": "hi"}, headers={"X-Sentinel-Key": bad_key})

    assert bad_key not in audit_log.read_text()


def test_run_uses_role_resolved_from_key(client, captured_pipeline):
    resp = client.post("/run", json={"task": "hi"}, headers={"X-Sentinel-Key": ANALYST_KEY})

    assert resp.status_code == 200
    assert captured_pipeline == [{"role": "analyst", "namespace": "general"}]
    assert resp.json()["role"] == "analyst"


def test_run_rejects_role_field_in_body(client, captured_pipeline):
    resp = client.post(
        "/run",
        json={"task": "hi", "role": "admin", "namespace": "hr"},
        headers={"X-Sentinel-Key": ANALYST_KEY},
    )

    assert resp.status_code == 422
    assert captured_pipeline == []


def test_analyst_key_cannot_reach_hr_namespace(client, audit_log):
    # Real pipeline: orchestrator_node blocks before any LLM call.
    resp = client.post(
        "/run", json={"task": "salaries", "namespace": "hr"},
        headers={"X-Sentinel-Key": ANALYST_KEY},
    )

    assert resp.status_code == 200
    assert resp.json()["blocked"] is True
    assert "cannot access namespace" in resp.json()["error"]
    assert "rbac_namespace_denied" in _audit_rules(audit_log)


def test_demo_mode_without_keys_runs_as_readonly(audit_log, captured_pipeline):
    app = create_app({"SENTINEL_DEMO_MODE": "1", "AUDIT_LOG_PATH": str(audit_log)})

    resp = TestClient(app).post("/run", json={"task": "hi"})

    assert resp.status_code == 200
    assert captured_pipeline[0]["role"] == "readonly"


# ── governance endpoints ───────────────────────────────────────────────────────

@pytest.mark.parametrize("method, path", [
    ("get", "/audit"),
    ("get", "/review/queue"),
    ("post", "/audit/rotate"),
])
def test_governance_endpoints_require_key(client, method, path):
    assert getattr(client, method)(path).status_code == 401


@pytest.mark.parametrize("key", [ADMIN_KEY, AUDITOR_KEY])
def test_audit_readable_by_admin_and_auditor(client, key):
    assert client.get("/audit", headers={"X-Sentinel-Key": key}).status_code == 200


def test_audit_not_readable_by_analyst(client, audit_log):
    resp = client.get("/audit", headers={"X-Sentinel-Key": ANALYST_KEY})

    assert resp.status_code == 403
    assert "auth_role_denied" in _audit_rules(audit_log)


def test_auditor_cannot_rotate_or_decide(client):
    headers = {"X-Sentinel-Key": AUDITOR_KEY}
    assert client.post("/audit/rotate", headers=headers).status_code == 403
    resp = client.post("/review/req-1/decide", json={"decision": "approve"}, headers=headers)
    assert resp.status_code == 403


def test_delete_audit_endpoint_is_gone(client):
    resp = client.delete("/audit", headers={"X-Sentinel-Key": ADMIN_KEY})
    assert resp.status_code == 405


def test_rotate_archives_log_and_leaves_fresh_file(client, audit_log):
    audit_log.write_text(json.dumps({"action": "DENY", "rule_name": "old"}) + "\n")

    resp = client.post("/audit/rotate", headers={"X-Sentinel-Key": ADMIN_KEY})

    assert resp.status_code == 200
    archive = audit_log.parent / resp.json()["archive"]
    assert "old" in archive.read_text()
    assert _audit_rules(audit_log) == ["audit_rotated"]
