import os

import pytest

# Paused runs and the review → thread map live in SQLite. Always override (not
# setdefault): inside the API container the env points at the live database.
os.environ["SENTINEL_CHECKPOINT_DB"] = ":memory:"


@pytest.fixture(autouse=True)
def _isolated_audit_log(tmp_path, monkeypatch):
    """Keep every test's audit writes out of the repo's logs/ directory."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(path))
    return path
