import os
from typing import Callable, Iterator, Mapping, Optional

import pytest
from fastapi import FastAPI

# Paused runs and the review → thread map live in SQLite. Always override (not
# setdefault): inside the API container the env points at the live database.
os.environ["SENTINEL_CHECKPOINT_DB"] = ":memory:"


@pytest.fixture(autouse=True)
def _isolated_audit_log(tmp_path, monkeypatch):
    """Keep every test's audit writes out of the repo's logs/ directory."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(path))
    return path


@pytest.fixture
def make_app() -> Iterator[Callable[[Optional[Mapping[str, str]]], FastAPI]]:
    """create_app() opens the review-map SQLite connection; only lifespan shutdown
    closes it, and a TestClient used without ``with`` never runs shutdown. Close
    every app built through this factory at teardown."""
    from api.main import create_app

    apps: list[FastAPI] = []

    def factory(env: Optional[Mapping[str, str]] = None) -> FastAPI:
        app = create_app(env)
        apps.append(app)
        return app

    yield factory
    for app in apps:
        app.state.review_threads.close()


@pytest.fixture(autouse=True, scope="session")
def _close_pipeline_db() -> Iterator[None]:
    """The orchestrator keeps one process-wide checkpoint connection; close it at exit."""
    yield
    import orchestrator.main as orch

    orch.reset_pipeline()
