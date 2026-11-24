"""
SentinelMesh FastAPI backend.

Run with the app factory: ``uvicorn --factory api.main:create_app``.

Endpoints (all except / and /health require an X-Sentinel-Key bound to a role):
  GET  /health                      — liveness check
  POST /run                         — trigger the LangGraph pipeline as the caller's role
  GET  /audit                       — tail the audit log            (admin, auditor)
  POST /audit/rotate                — archive the audit log         (admin)
  GET  /review/queue                — list HUMAN_REVIEW items       (admin, auditor)
  POST /review/{request_id}/decide  — approve/reject and resume     (admin)
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel

from api.auth import audit_role_spoof, caller_role, ensure_bootable, load_auth_config, require_roles
from api.rate_limit import TokenBucketLimiter
from api.review import GOVERNANCE_READERS, GOVERNANCE_WRITERS, tail_file
from api.review import router as review_router
from api.schemas import RunRequest, RunResponse, to_run_response
from api.state import ReviewThreads, Settings, review_lock, review_threads, settings, track_if_paused
from audit.writer import default_audit_path, is_strict, rotate_audit_log
from config import get_settings, load_env_file

logger = logging.getLogger(__name__)

router = APIRouter()


def create_app(env: Optional[Mapping[str, str]] = None) -> FastAPI:
    """Build the API. Refuses to start without API keys unless SENTINEL_DEMO_MODE=1."""
    if env is None:
        load_env_file()
        env = os.environ
    auth = load_auth_config(env)
    ensure_bootable(auth)
    if auth.is_open_demo:
        logger.warning("SENTINEL_DEMO_MODE=1 with no API keys: API is UNAUTHENTICATED")

    audit_path = default_audit_path(env)
    app = FastAPI(
        title="SentinelMesh API",
        description="Policy-enforced multi-agent orchestration",
        version="0.3.0",
        lifespan=_lifespan,
    )
    app.state.auth = auth
    app.state.settings = Settings(
        audit_log_path=audit_path,
        decisions_path=audit_path.parent / "review_decisions.jsonl",
        audit_strict=is_strict(env),
    )
    app.state.review_threads = ReviewThreads(
        db_path=env.get("SENTINEL_CHECKPOINT_DB") or get_settings().sentinel_checkpoint_db,
    )
    app.state.rate_limiter = TokenBucketLimiter()
    app.state.failed_auth_limiter = TokenBucketLimiter()
    app.add_exception_handler(RequestValidationError, _audit_then_reject)
    app.include_router(router)
    app.include_router(review_router)
    return app


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    await run_in_threadpool(_discard_orphaned_runs, app)
    yield
    app.state.review_threads.close()


def _discard_orphaned_runs(app: FastAPI) -> None:
    """At startup no run is in flight, so any checkpoint without a live review mapping
    is unreachable (expired or claimed-then-crashed) and only keeps PII at rest."""
    from orchestrator.main import discard_orphaned_threads

    removed = discard_orphaned_threads(app.state.review_threads.live_thread_ids())
    if removed:
        logger.info("discarded %d orphaned paused-run checkpoint(s)", len(removed))


async def _audit_then_reject(request: Request, exc: RequestValidationError):
    # The audit append takes a file lock: keep blocking I/O off the event loop.
    await run_in_threadpool(audit_role_spoof, request, exc.errors())
    return await request_validation_exception_handler(request, exc)


# ── schemas ────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str


class RotateResponse(BaseModel):
    status: str
    archive: str


# ── endpoints ──────────────────────────────────────────────────────────────────

@router.get("/")
def root():
    return {
        "message": "SentinelMesh API is running",
        "docs": "/docs",
        "health": "/health"
    }


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.post("/run", response_model=RunResponse)
def run_pipeline_endpoint(
    request: Request,
    req: RunRequest,
    role: str = Depends(caller_role),
) -> RunResponse:
    from orchestrator.main import run_pipeline

    try:
        result = run_pipeline(
            task=req.task,
            document=req.document,
            role=role,
            namespace=req.namespace,
        )
    except Exception as exc:
        logger.exception("pipeline run failed for role=%s", role)
        raise HTTPException(status_code=500, detail="Pipeline execution failed") from exc

    response = to_run_response(result)
    track_if_paused(request, response)
    return response


@router.post("/audit/rotate", response_model=RotateResponse)
def rotate_audit(
    request: Request,
    role: str = Depends(require_roles(*GOVERNANCE_WRITERS)),
) -> RotateResponse:
    """Archive the audit log and review decisions. History is never deleted."""
    if review_threads(request).has_paused():
        # Rotation would drop the HUMAN_REVIEW entries that paused runs are decided by.
        raise HTTPException(status_code=409, detail="Runs are paused for human review; decide them before rotating")
    cfg = settings(request)
    with review_lock:
        archive = rotate_audit_log(cfg.audit_log_path, cfg.decisions_path, rotated_by=role)
    return RotateResponse(status="rotated", archive=archive.name)


@router.get("/audit", dependencies=[Depends(require_roles(*GOVERNANCE_READERS))])
def get_audit_log(request: Request, limit: int = Query(default=50, ge=1, le=1000)) -> list[dict]:
    audit_path = settings(request).audit_log_path
    if not audit_path.exists():
        return []

    entries = []
    for line in tail_file(audit_path, limit):
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries
