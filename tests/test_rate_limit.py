"""Per-API-key token bucket (Role.rate_limit_rpm) on every authenticated endpoint."""

import json

import pytest
from fastapi.testclient import TestClient

from api.rate_limit import TokenBucketLimiter
from rbac.roles import get_role

AUDITOR_KEY = "auditor-key-0123456789abcd"
ADMIN_KEY = "admin-key-0123456789abcdef"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_bucket_allows_rpm_then_denies():
    clock = FakeClock()
    limiter = TokenBucketLimiter(clock=clock)

    results = [limiter.check("k", rpm=3).allowed for _ in range(4)]

    assert results == [True, True, True, False]


def test_bucket_refills_over_time():
    clock = FakeClock()
    limiter = TokenBucketLimiter(clock=clock)
    for _ in range(3):
        limiter.check("k", rpm=3)
    denied = limiter.check("k", rpm=3)

    clock.now += 20  # 3 rpm = one token every 20 s

    assert denied.retry_after_seconds == pytest.approx(20, abs=1)
    assert limiter.check("k", rpm=3).allowed
    assert not limiter.check("k", rpm=3).allowed


def test_buckets_are_independent_per_key():
    limiter = TokenBucketLimiter(clock=FakeClock())
    limiter.check("a", rpm=1)

    assert not limiter.check("a", rpm=1).allowed
    assert limiter.check("b", rpm=1).allowed


def test_nonpositive_rpm_is_rejected():
    with pytest.raises(ValueError):
        TokenBucketLimiter().check("k", rpm=0)


@pytest.fixture
def client(_isolated_audit_log, make_app):
    env = {
        "SENTINEL_CALLER_KEYS": json.dumps({AUDITOR_KEY: "auditor", ADMIN_KEY: "admin"}),
        "AUDIT_LOG_PATH": str(_isolated_audit_log),
    }
    app = make_app(env)
    app.state.rate_limiter = TokenBucketLimiter(clock=FakeClock())
    return TestClient(app)


def test_api_returns_429_after_role_limit_and_audits(client, _isolated_audit_log):
    rpm = get_role("auditor").rate_limit_rpm
    headers = {"X-Sentinel-Key": AUDITOR_KEY}
    statuses = [client.get("/audit?limit=1", headers=headers).status_code for _ in range(rpm)]

    limited = client.get("/audit?limit=1", headers=headers)

    assert set(statuses) == {200}
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1
    rules = [json.loads(line)["rule_name"] for line in _isolated_audit_log.read_text().splitlines()]
    assert rules.count("rate_limited") == 1


def test_one_key_exhausted_does_not_limit_another(client):
    rpm = get_role("auditor").rate_limit_rpm
    for _ in range(rpm + 1):
        client.get("/audit?limit=1", headers={"X-Sentinel-Key": AUDITOR_KEY})

    assert client.get("/audit?limit=1", headers={"X-Sentinel-Key": ADMIN_KEY}).status_code == 200


def test_health_is_not_rate_limited(client):
    assert all(client.get("/health").status_code == 200 for _ in range(100))


def test_only_first_denial_per_exhaustion_is_flagged():
    limiter = TokenBucketLimiter(clock=FakeClock())
    limiter.check("k", rpm=1)

    first, second = limiter.check("k", rpm=1), limiter.check("k", rpm=1)

    assert first.should_audit and not second.should_audit


def test_audit_written_once_per_exhaustion(client, _isolated_audit_log):
    rpm = get_role("auditor").rate_limit_rpm
    for _ in range(rpm + 5):
        client.get("/audit?limit=1", headers={"X-Sentinel-Key": AUDITOR_KEY})

    rules = [json.loads(line)["rule_name"] for line in _isolated_audit_log.read_text().splitlines()]
    assert rules.count("rate_limited") == 1


def test_invalid_keys_are_throttled_per_client(client, _isolated_audit_log):
    from api.auth import FAILED_AUTH_PER_MINUTE

    codes = [client.get("/audit", headers={"X-Sentinel-Key": f"wrong-key-{i:012d}"}).status_code
             for i in range(FAILED_AUTH_PER_MINUTE + 3)]

    assert codes[:FAILED_AUTH_PER_MINUTE] == [401] * FAILED_AUTH_PER_MINUTE
    assert codes[FAILED_AUTH_PER_MINUTE:] == [429] * 3
    # Throttled attempts are not individually audited (bounded log growth).
    rules = [json.loads(line)["rule_name"] for line in _isolated_audit_log.read_text().splitlines()]
    assert rules.count("auth_invalid_key") == FAILED_AUTH_PER_MINUTE
    assert rules.count("auth_failures_throttled") == 1


def test_tracked_buckets_are_capped():
    clock = FakeClock()
    limiter = TokenBucketLimiter(clock=clock, max_buckets=3)
    for ip in ["a", "b", "c", "d"]:
        clock.now += 1
        limiter.check(ip, rpm=5)

    assert len(limiter) == 3
