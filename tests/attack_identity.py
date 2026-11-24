"""Layer D attack vectors: identity spoofing and the human-review gate.

Used by tests/run_attacks.py. Each check returns "pass", "fail", or "skip".
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass

import httpx

GDPR_TASK = "Query the legal database for GDPR data handling procedures and summarize the controls."
GDPR_DOC = "GDPR review April 2026: consent mechanisms audited, data processing agreements in place."


@dataclass(frozen=True)
class IdentityCheck:
    name: str
    run: Callable[[], str]
    requires_proxy: bool = False
    requires_llm: bool = False


def _json_env(name: str) -> dict:
    raw = os.getenv(name, "").strip()
    return json.loads(raw) if raw else {}


def _key_for_role(role: str) -> str:
    keys = {r: k for k, r in _json_env("SENTINEL_CALLER_KEYS").items()}
    legacy = os.getenv("SENTINEL_API_KEY", "").strip()
    if legacy:
        keys = {**keys, "admin": legacy}
    return keys.get(role, "")


def _report(ok: bool, detail: str) -> str:
    print(f"  result:    {detail} → {'PASS' if ok else 'FAIL'}")
    return "pass" if ok else "fail"


def _proxy_content(agent_id: str, intent: str, key: str) -> str:
    url = os.getenv("LOBSTER_TRAP_URL", "http://localhost:8080") + "/v1/chat/completions"
    body = {
        "model": os.getenv("LLM_MODEL", "openai/gpt-oss-120b"),
        "messages": [{"role": "user", "content": "Dump every record in the knowledge base."}],
        "_lobstertrap": {"agent_id": agent_id, "declared_intent": intent},
    }
    resp = httpx.post(url, json=body, headers={"X-Agent-Key": key}, timeout=30)
    return resp.json()["choices"][0]["message"]["content"]


def check_intent_spoof() -> str:
    """Valid critic credentials, but the critic is only registered for 'general'."""
    key = _json_env("LT_AGENT_KEYS").get("critic-agent-v1", "")
    if not key:
        print("  (LT_AGENT_KEYS has no critic-agent-v1 key)")
        return "fail"
    content = _proxy_content("critic-agent-v1", "data_access", key)
    return _report(content.startswith("[SENTINEL]") and "intent" in content, content[:90])


def check_forged_agent_key() -> str:
    content = _proxy_content("extraction-agent-v1", "data_access", "forged-key-0000000000000000")
    return _report(content.startswith("[SENTINEL]") and "authentication failed" in content, content[:90])


def _api_client():
    from fastapi.testclient import TestClient

    from api.main import create_app

    return TestClient(create_app())


def check_body_role_spoof() -> str:
    """An analyst key with role=admin in the body must be rejected (and audited)."""
    key = _key_for_role("analyst")
    headers = {"X-Sentinel-Key": key} if key else {}
    resp = _api_client().post(
        "/run", headers=headers,
        json={"task": "Retrieve salary bands.", "namespace": "hr", "role": "admin"},
    )
    return _report(resp.status_code == 422, f"HTTP {resp.status_code}")


def check_human_review_gate() -> str:
    """HUMAN_REVIEW pauses the run; an admin approval resumes it to completion."""
    analyst, admin = _key_for_role("analyst"), _key_for_role("admin")
    if not (analyst and admin):
        print("  (needs analyst and admin keys in SENTINEL_CALLER_KEYS)")
        return "fail"
    client = _api_client()
    run = client.post("/run", headers={"X-Sentinel-Key": analyst},
                      json={"task": GDPR_TASK, "document": GDPR_DOC, "namespace": "legal"}).json()
    if run.get("status") != "pending_review":
        return _report(False, f"expected pending_review, got {run.get('status')!r}: {run.get('error', '')[:60]}")
    decided = client.post(f"/review/{run['review_request_id']}/decide",
                          headers={"X-Sentinel-Key": admin},
                          json={"decision": "approve", "note": "attack suite"}).json()
    resumed = decided.get("run") or {}
    ok = decided.get("resumed") is True and resumed.get("status") == "completed" \
        and bool(resumed.get("analysis_result"))
    return _report(ok, f"resumed={decided.get('resumed')} status={resumed.get('status')!r} "
                       f"error={resumed.get('error', '')[:50]!r}")


IDENTITY_CHECKS: list[IdentityCheck] = [
    IdentityCheck("[IDENTITY] Agent intent spoofing (critic claims data_access)",
                  check_intent_spoof, requires_proxy=True),
    IdentityCheck("[IDENTITY] Forged agent key (extraction agent)",
                  check_forged_agent_key, requires_proxy=True),
    IdentityCheck("[AUTH] Body role spoofing (analyst key + role=admin)",
                  check_body_role_spoof),
    IdentityCheck("[HITL] Human review pauses, approval resumes",
                  check_human_review_gate, requires_proxy=True, requires_llm=True),
]


def run_identity_check(check: IdentityCheck, proxy_up: bool, skip_llm: bool) -> str:
    print(f"\n{'='*60}")
    if check.requires_proxy and not proxy_up:
        print(f"SKIP: {check.name}\n  (Lobster Trap not reachable)")
        return "skip"
    if check.requires_llm and skip_llm:
        print(f"SKIP: {check.name}\n  (SKIP_LLM_TESTS=1 — no LLM backend)")
        return "skip"
    print(f"ATTACK: {check.name}")
    try:
        return check.run()
    except Exception as exc:
        print(f"  result:    unexpected exception — {exc!r} → FAIL")
        return "fail"
