"""Human review queue and decisions.

A HUMAN_REVIEW verdict pauses the pipeline run (see orchestrator.main). Deciding an
item records the decision first (Lobster Trap verifies approvals from that file), then
resumes the paused run: approve replays the held call, reject ends it as blocked.
If no paused run exists (e.g. the API restarted), the decision is recorded only.
"""

from __future__ import annotations

import json
import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.auth import require_roles
from api.schemas import RunResponse, to_run_response
from api.state import review_lock, review_threads, settings, track_if_paused
from audit.writer import append_unless_conflict

logger = logging.getLogger(__name__)

GOVERNANCE_READERS = ("admin", "auditor")
GOVERNANCE_WRITERS = ("admin",)
MAX_AUDIT_READ_LINES = 10_000
MAX_NOTE_CHARS = 1000
QueueStatus = Literal["pending", "approved", "rejected", "all"]

router = APIRouter()


class ReviewDecision(BaseModel):
    decision: Literal["approve", "reject"]
    note: str = Field(default="", max_length=MAX_NOTE_CHARS)


class ReviewItem(BaseModel):
    request_id: str
    timestamp: str
    agent_id: str
    risk_score: float
    rule_name: str
    raw: dict
    decision: str | None
    note: str
    resumable: bool = False


class DecisionResult(ReviewItem):
    resumed: bool = False
    run: Optional[RunResponse] = None


def tail_file(path: Path, n: int) -> list[str]:
    """Read at most the last n lines of a file without loading it all into memory."""
    with path.open() as fh:
        return list(deque(fh, maxlen=n))


def _parse_ts(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in tail_file(path, MAX_AUDIT_READ_LINES):
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _read_human_review(audit_path: Path) -> list[dict]:
    return [e for e in _read_jsonl(audit_path) if e.get("action") == "HUMAN_REVIEW"]


def _read_decisions(decisions_path: Path) -> dict[str, dict]:
    """Decisions are write-once: the first one for a request ID wins (as in the proxy)."""
    decisions: dict[str, dict] = {}
    for d in _read_jsonl(decisions_path):
        rid = d.get("request_id")
        if rid and rid not in decisions:
            decisions = {**decisions, rid: d}
    return decisions


def _is_stale(entry: dict, decision: dict) -> bool:
    """A decision older than the audit entry belongs to an earlier proxy run that
    reused the same sequential request_id."""
    entry_ts = _parse_ts(entry.get("timestamp", ""))
    decided_ts = _parse_ts(decision.get("decided_at", ""))
    return bool(entry_ts and decided_ts and entry_ts > decided_ts)


def _to_review_item(entry: dict, decisions: dict[str, dict], resumable: bool) -> ReviewItem:
    rid = entry.get("request_id", "")
    dec = decisions.get(rid)
    if dec and _is_stale(entry, dec):
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
        resumable=resumable and dec is None,
    )


@router.get(
    "/review/queue",
    response_model=list[ReviewItem],
    dependencies=[Depends(require_roles(*GOVERNANCE_READERS))],
)
def get_review_queue(request: Request, status: QueueStatus = "pending") -> list[ReviewItem]:
    cfg = settings(request)
    threads = review_threads(request)
    decisions = _read_decisions(cfg.decisions_path)
    items = [
        _to_review_item(e, decisions, threads.is_resumable(e.get("request_id", "")))
        for e in _read_human_review(cfg.audit_log_path)
    ]
    if status == "all":
        return items
    wanted = {"pending": None, "approved": "approve", "rejected": "reject"}[status]
    return [i for i in items if i.decision == wanted]


def _record_decision(request: Request, request_id: str, body: ReviewDecision, role: str) -> tuple[dict, dict]:
    cfg = settings(request)
    entry_map = {e.get("request_id", ""): e for e in _read_human_review(cfg.audit_log_path)}
    if request_id not in entry_map:
        raise HTTPException(status_code=404, detail=f"No HUMAN_REVIEW entry found for request_id {request_id!r}")

    record = {
        "request_id": request_id,
        "decision": body.decision,
        "note": body.note,
        "decided_at": datetime.now(timezone.utc).isoformat(),
        "decided_by_role": role,
    }
    entry = entry_map[request_id]

    def live_decision(rows: list[dict]) -> Optional[dict]:
        first = next((r for r in rows if r.get("request_id") == request_id), None)
        return first if first and not _is_stale(entry, first) else None

    with review_lock:
        existing = append_unless_conflict(cfg.decisions_path, record, live_decision)
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"request_id {request_id!r} already decided as {existing.get('decision')!r}")
    return entry, record


def _resume(request: Request, thread_id: Optional[str], body: ReviewDecision) -> Optional[RunResponse]:
    if thread_id is None:
        return None
    from orchestrator.main import ReviewNotPending, resume_pipeline

    try:
        run = to_run_response(resume_pipeline(thread_id, body.decision, body.note))
    except ReviewNotPending:
        logger.warning("review thread %s no longer paused; decision recorded only", thread_id)
        return None
    track_if_paused(request, run)  # the replay (or a later step) may be held again
    return run


@router.post("/review/{request_id}/decide", response_model=DecisionResult)
def decide_review_item(
    request: Request,
    request_id: str,
    body: ReviewDecision,
    role: str = Depends(require_roles(*GOVERNANCE_WRITERS)),
) -> DecisionResult:
    entry, record = _record_decision(request, request_id, body, role)
    # Claim after recording: a 404/409 must leave the paused run resumable.
    thread_id = review_threads(request).claim(request_id)
    try:
        run = _resume(request, thread_id, body)
    except Exception as exc:
        logger.exception("resuming review %s failed", request_id)
        raise HTTPException(status_code=500, detail="Decision recorded, but resuming the run failed") from exc
    item = _to_review_item(entry, {request_id: record}, resumable=False)
    return DecisionResult(**item.model_dump(), resumed=run is not None, run=run)
