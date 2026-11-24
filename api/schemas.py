"""Request/response models shared by the API routers."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RunStatus = Literal["completed", "blocked", "pending_review"]


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
    status: RunStatus
    blocked: bool
    error: str
    extracted_data: str
    analysis_result: str
    action_result: str
    critic_reviews: list[str]
    thread_id: str = ""
    review_request_id: str = Field(default="", description="Set when status is pending_review")


def to_run_response(result: dict) -> RunResponse:
    status = result.get("status") or ("blocked" if result["blocked"] else "completed")
    return RunResponse(
        task=result["task"],
        role=result["role"],
        namespace=result["namespace"],
        status=status,
        blocked=result["blocked"],
        error=result["error"],
        extracted_data=result["extracted_data"],
        analysis_result=result["analysis_result"],
        action_result=result["action_result"],
        critic_reviews=result["critic_reviews"],
        thread_id=result.get("thread_id", ""),
        review_request_id=result.get("review_request_id", ""),
    )
