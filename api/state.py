"""Per-app state shared by the API routers."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from fastapi import Request


@dataclass(frozen=True)
class Settings:
    audit_log_path: Path
    decisions_path: Path
    audit_strict: bool


PAUSED_RUN_TTL_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class _Paused:
    thread_id: str
    paused_at: float


@dataclass
class ReviewThreads:
    """Maps a held proxy request ID to the paused pipeline thread that can resume it.

    In memory only: paused runs (MemorySaver) do not survive an API restart either.
    Runs left undecided longer than ttl_seconds are expired so memory stays bounded.
    """

    ttl_seconds: float = PAUSED_RUN_TTL_SECONDS
    clock: Callable[[], float] = time.monotonic
    _threads: dict[str, _Paused] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def register(self, request_id: str, thread_id: str) -> list[str]:
        """Track a paused run. Returns thread IDs that expired and should be discarded."""
        with self._lock:
            now = self.clock()
            live = {k: v for k, v in self._threads.items() if now - v.paused_at <= self.ttl_seconds}
            expired = [v.thread_id for k, v in self._threads.items() if k not in live]
            self._threads = {**live, request_id: _Paused(thread_id, now)}
            return expired

    def is_resumable(self, request_id: str) -> bool:
        with self._lock:
            return request_id in self._threads

    def has_paused(self) -> bool:
        with self._lock:
            return bool(self._threads)

    def claim(self, request_id: str) -> Optional[str]:
        """Atomically take the thread for a request; only one decider ever gets it."""
        with self._lock:
            paused = self._threads.get(request_id)
            if paused is not None:
                self._threads = {k: v for k, v in self._threads.items() if k != request_id}
            return paused.thread_id if paused else None


# Serialises appends/rotation of the review decisions file within this process.
review_lock = threading.Lock()


def settings(request: Request) -> Settings:
    return request.app.state.settings


def review_threads(request: Request) -> ReviewThreads:
    return request.app.state.review_threads


def track_if_paused(request: Request, run: object) -> None:
    """Register a pending_review run so a decision can resume it; drop expired ones."""
    if getattr(run, "status", None) != "pending_review":
        return
    from orchestrator.main import discard_thread

    for thread_id in review_threads(request).register(run.review_request_id, run.thread_id):
        discard_thread(thread_id)
