"""
SentinelMesh FastAPI backend.

Run with the app factory: ``uvicorn --factory api.main:create_app``.

Endpoints (all except / and /health require an X-Sentinel-Key bound to a role):
  GET  /health                      — liveness check
  POST /run                         — trigger the LangGraph pipeline as the caller's role
  GET  /audit                       — tail the audit log            (admin, auditor)
  POST /audit/rotate                — archive the audit log         (admin)
  GET  /review/queue                — list HUMAN_REVIEW items       (admin, auditor)
  POST /review/{request_id}/decide  — approve or reject an item     (admin)
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from api.auth import caller_role, ensure_bootable, load_auth_config, require_roles
from audit.writer import append_entry, default_audit_path, is_strict, rotate_audit_log

logger = logging.getLogger(__name__)

GOVERNANCE_READERS = ("admin", "auditor")
GOVERNANCE_WRITERS = ("admin",)

_review_lock = threading.Lock()
router = APIRouter()


@dataclass(frozen=True)
class Settings:
    audit_log_path: Path
    decisions_path: Path
    audit_strict: bool


def create_app(env: Optional[Mapping[str, str]] = None) -> FastAPI:
    """Build the API. Refuses to start without API keys unless SENTINEL_DEMO_MODE=1."""
    if env is None:
        load_dotenv()
        env = os.environ
    auth = load_auth_config(env)
    ensure_bootable(auth)
    if auth.is_open_demo:
        logger.warning("SENTINEL_DEMO_MODE=1 with no API keys: API is UNAUTHENTICATED")

    audit_path = default_audit_path(env)
    app = FastAPI(
        title="SentinelMesh API",
        description="Policy-enforced multi-agent orchestration",
        version="0.2.0",
    )
    app.state.auth = auth
    app.state.settings = Settings(
        audit_log_path=audit_path,
        decisions_path=audit_path.parent / "review_decisions.jsonl",
        audit_strict=is_strict(env),
    )
    app.include_router(router)
    return app


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ── schemas ────────────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    # Unknown fields (notably "role") are rejected: the role comes from the API key.
    model_config = ConfigDict(extra="forbid")

    task: str = Field(..., description="Natural-language task for the agent pipeline")
    document: str = Field(default="", description="Source document to process")
    namespace: str = Field(default="general", description="ChromaDB namespace to access", pattern=r"^[a-zA-Z0-9_-]+$")


class RunResponse(BaseModel):
    task: str
    role: str
    namespace: str
    blocked: bool
    error: str
    extracted_data: str
    analysis_result: str
    action_result: str
    critic_reviews: list[str]


class HealthResponse(BaseModel):
    status: str


class ReviewDecision(BaseModel):
    decision: Literal["approve", "reject"]
    note: str = ""


class ReviewItem(BaseModel):
    request_id: str
    timestamp: str
    agent_id: str
    risk_score: float
    rule_name: str
    raw: dict
    decision: str | None
    note: str


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
def run_pipeline_endpoint(req: RunRequest, role: str = Depends(caller_role)) -> RunResponse:
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

    return RunResponse(
        task=result["task"],
        role=result["role"],
        namespace=result["namespace"],
        blocked=result["blocked"],
        error=result["error"],
        extracted_data=result["extracted_data"],
        analysis_result=result["analysis_result"],
        action_result=result["action_result"],
        critic_reviews=result["critic_reviews"],
    )


# ── review queue helpers ───────────────────────────────────────────────────────

MAX_AUDIT_READ_LINES = 10_000


def _tail_file(path: Path, n: int) -> list[str]:
    """Read at most the last n lines of a file without loading it all into memory."""
    with path.open() as fh:
        return list(deque(fh, maxlen=n))


def _read_audit_human_review(audit_path: Path) -> list[dict]:
    if not audit_path.exists():
        return []
    entries = []
    for line in _tail_file(audit_path, MAX_AUDIT_READ_LINES):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("action") == "HUMAN_REVIEW":
            entries.append(entry)
    return entries


def _read_decisions(decisions_path: Path) -> dict[str, dict]:
    if not decisions_path.exists():
        return {}
    decisions: dict[str, dict] = {}
    for line in _tail_file(decisions_path, MAX_AUDIT_READ_LINES):
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        decisions[d["request_id"]] = d
    return decisions


def _to_review_item(entry: dict, decisions: dict[str, dict]) -> ReviewItem:
    rid = entry.get("request_id", "")
    dec = decisions.get(rid)
    # If the audit entry is newer than the decision, the decision is from a previous
    # Lobster Trap run that reused the same request_id — treat as pending.
    if dec:
        entry_ts = entry.get("timestamp", "")
        decided_ts = dec.get("decided_at", "")
        if entry_ts and decided_ts and _parse_ts(entry_ts) > _parse_ts(decided_ts):
            dec = None
    return ReviewItem(
        request_id=rid,
        timestamp=entry.get("timestamp", ""),
        agent_id=entry.get("agent_id", ""),
        risk_score=float(entry.get("risk_score", 0.0)),
        rule_name=entry.get("rule_name", ""),
        raw=entry,
        decision=dec["decision"] if dec else None,
        note=dec.get("note", "") if dec else "",
    )


# ── endpoints ──────────────────────────────────────────────────────────────────

class RotateResponse(BaseModel):
    status: str
    archive: str


@router.post("/audit/rotate", response_model=RotateResponse)
def rotate_audit(
    request: Request,
    role: str = Depends(require_roles(*GOVERNANCE_WRITERS)),
) -> RotateResponse:
    """Archive the audit log and review decisions. History is never deleted."""
    settings = _settings(request)
    with _review_lock:
        archive = rotate_audit_log(settings.audit_log_path, settings.decisions_path, rotated_by=role)
    return RotateResponse(status="rotated", archive=archive.name)


@router.get("/audit", dependencies=[Depends(require_roles(*GOVERNANCE_READERS))])
def get_audit_log(request: Request, limit: int = Query(default=50, ge=1, le=1000)) -> list[dict]:
    audit_path = _settings(request).audit_log_path
    if not audit_path.exists():
        return []

    entries = []
    for line in _tail_file(audit_path, limit):
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


@router.get(
    "/review/queue",
    response_model=list[ReviewItem],
    dependencies=[Depends(require_roles(*GOVERNANCE_READERS))],
)
def get_review_queue(request: Request, status: str = "pending") -> list[ReviewItem]:
    settings = _settings(request)
    hr_entries = _read_audit_human_review(settings.audit_log_path)
    decisions = _read_decisions(settings.decisions_path)
    items = [_to_review_item(e, decisions) for e in hr_entries]

    if status == "pending":
        return [i for i in items if i.decision is None]
    if status == "approved":
        return [i for i in items if i.decision == "approve"]
    if status == "rejected":
        return [i for i in items if i.decision == "reject"]
    return items  # "all"


@router.post("/review/{request_id}/decide", response_model=ReviewItem)
def decide_review_item(
    request: Request,
    request_id: str,
    body: ReviewDecision,
    role: str = Depends(require_roles(*GOVERNANCE_WRITERS)),
) -> ReviewItem:
    settings = _settings(request)
    hr_entries = _read_audit_human_review(settings.audit_log_path)
    entry_map = {e.get("request_id", ""): e for e in hr_entries}

    if request_id not in entry_map:
        raise HTTPException(status_code=404, detail=f"No HUMAN_REVIEW entry found for request_id {request_id!r}")

    decisions = _read_decisions(settings.decisions_path)
    if request_id in decisions:
        entry_ts = entry_map[request_id].get("timestamp", "")
        decided_ts = decisions[request_id].get("decided_at", "")
        stale = entry_ts and decided_ts and _parse_ts(entry_ts) > _parse_ts(decided_ts)
        if not stale:
            raise HTTPException(status_code=409, detail=f"request_id {request_id!r} already decided as {decisions[request_id]['decision']!r}")

    record = {
        "request_id": request_id,
        "decision": body.decision,
        "note": body.note,
        "decided_at": datetime.now(timezone.utc).isoformat(),
        "decided_by_role": role,
    }
    with _review_lock:
        append_entry(record, path=settings.decisions_path, strict=True)

    decisions[request_id] = record
    return _to_review_item(entry_map[request_id], decisions)
