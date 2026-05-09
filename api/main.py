"""
SentinelMesh FastAPI backend.

Endpoints:
  GET  /health                      — liveness check
  POST /run                         — trigger the LangGraph pipeline
  GET  /audit                       — tail the Lobster Trap audit log
  GET  /review/queue                — list HUMAN_REVIEW items (pending by default)
  POST /review/{request_id}/decide  — approve or reject a flagged item
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

load_dotenv()

app = FastAPI(
    title="SentinelMesh API",
    description="Policy-enforced multi-agent orchestration",
    version="0.1.0",
)

AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", "logs/audit.jsonl"))
REVIEW_DECISIONS_PATH = AUDIT_LOG_PATH.parent / "review_decisions.jsonl"


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ── schemas ────────────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    task: str = Field(..., description="Natural-language task for the agent pipeline")
    document: str = Field(default="", description="Source document to process")
    role: str = Field(default="readonly", description="RBAC role of the requester")
    namespace: str = Field(default="general", description="ChromaDB namespace to access")


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

@app.get("/")
def root():
    return {
        "message": "SentinelMesh API is running",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/run", response_model=RunResponse)
def run_pipeline_endpoint(req: RunRequest) -> RunResponse:
    from orchestrator.main import run_pipeline

    try:
        result = run_pipeline(
            task=req.task,
            document=req.document,
            role=req.role,
            namespace=req.namespace,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

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

def _read_audit_human_review() -> list[dict]:
    if not AUDIT_LOG_PATH.exists():
        return []
    entries = []
    for line in AUDIT_LOG_PATH.read_text().strip().splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("action") == "HUMAN_REVIEW":
            entries.append(entry)
    return entries


def _read_decisions() -> dict[str, dict]:
    if not REVIEW_DECISIONS_PATH.exists():
        return {}
    decisions: dict[str, dict] = {}
    for line in REVIEW_DECISIONS_PATH.read_text().strip().splitlines():
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

@app.get("/audit")
def get_audit_log(limit: int = 50) -> list[dict]:
    if not AUDIT_LOG_PATH.exists():
        return []

    lines = AUDIT_LOG_PATH.read_text().strip().splitlines()
    tail = lines[-limit:] if len(lines) > limit else lines

    entries = []
    for line in tail:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


@app.get("/review/queue", response_model=list[ReviewItem])
def get_review_queue(status: str = "pending") -> list[ReviewItem]:
    hr_entries = _read_audit_human_review()
    decisions = _read_decisions()
    items = [_to_review_item(e, decisions) for e in hr_entries]

    if status == "pending":
        return [i for i in items if i.decision is None]
    if status == "approved":
        return [i for i in items if i.decision == "approve"]
    if status == "rejected":
        return [i for i in items if i.decision == "reject"]
    return items  # "all"


@app.post("/review/{request_id}/decide", response_model=ReviewItem)
def decide_review_item(request_id: str, body: ReviewDecision) -> ReviewItem:
    hr_entries = _read_audit_human_review()
    entry_map = {e.get("request_id", ""): e for e in hr_entries}

    if request_id not in entry_map:
        raise HTTPException(status_code=404, detail=f"No HUMAN_REVIEW entry found for request_id {request_id!r}")

    decisions = _read_decisions()
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
    }
    with REVIEW_DECISIONS_PATH.open("a") as fh:
        fh.write(json.dumps(record) + "\n")

    decisions[request_id] = record
    return _to_review_item(entry_map[request_id], decisions)
