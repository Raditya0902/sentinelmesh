"""Per-app state shared by the API routers."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from fastapi import Request

import storage


@dataclass(frozen=True)
class Settings:
    audit_log_path: Path
    decisions_path: Path
    audit_strict: bool


PAUSED_RUN_TTL_SECONDS = 24 * 60 * 60

_SCHEMA = """
CREATE TABLE IF NOT EXISTS review_threads (
    request_id TEXT PRIMARY KEY,
    thread_id  TEXT NOT NULL,
    paused_at  REAL NOT NULL
)
"""


class ReviewThreads:
    """Maps a held proxy request ID to the paused pipeline thread that can resume it.

    Stored in SQLite next to the LangGraph checkpoints, so a restarted API can still
    resume runs that were paused before it went down. Every operation is one
    transaction, so ``claim`` is single-use even across processes. Runs left
    undecided longer than ``ttl_seconds`` (wall clock) are expired.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        ttl_seconds: float = PAUSED_RUN_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._lock = threading.Lock()
        self._conn = storage.connect(db_path, isolation_level=None)
        self._conn.execute(_SCHEMA)
        self.closed = False

    def close(self) -> None:
        with self._lock:
            self._conn.close()
            self.closed = True

    def __enter__(self) -> "ReviewThreads":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def register(self, request_id: str, thread_id: str) -> list[str]:
        """Track a paused run. Returns thread IDs that expired and should be discarded."""
        now = self.clock()
        cutoff = now - self.ttl_seconds
        with self._tx() as conn:
            expired = [row[0] for row in conn.execute(
                "SELECT thread_id FROM review_threads WHERE paused_at < ?", (cutoff,))]
            conn.execute("DELETE FROM review_threads WHERE paused_at < ?", (cutoff,))
            conn.execute(
                "INSERT OR REPLACE INTO review_threads (request_id, thread_id, paused_at) VALUES (?, ?, ?)",
                (request_id, thread_id, now),
            )
        return expired

    def _cutoff(self) -> float:
        return self.clock() - self.ttl_seconds

    def is_resumable(self, request_id: str) -> bool:
        with self._tx() as conn:
            row = conn.execute("SELECT 1 FROM review_threads WHERE request_id = ? AND paused_at >= ?",
                               (request_id, self._cutoff())).fetchone()
        return row is not None

    def has_paused(self) -> bool:
        """Live (unexpired) paused runs only: an abandoned run must not block rotation."""
        with self._tx() as conn:
            return conn.execute("SELECT 1 FROM review_threads WHERE paused_at >= ? LIMIT 1",
                                (self._cutoff(),)).fetchone() is not None

    def live_thread_ids(self) -> set[str]:
        with self._tx() as conn:
            rows = conn.execute("SELECT thread_id FROM review_threads WHERE paused_at >= ?",
                                (self._cutoff(),)).fetchall()
        return {r[0] for r in rows}

    def claim(self, request_id: str) -> Optional[str]:
        """Atomically take the thread for a request; only one decider ever gets it."""
        with self._tx() as conn:
            row = conn.execute(
                "SELECT thread_id FROM review_threads WHERE request_id = ? AND paused_at >= ?",
                (request_id, self._cutoff())).fetchone()
            if row is not None:
                conn.execute("DELETE FROM review_threads WHERE request_id = ?", (request_id,))
        return row[0] if row else None


# Serialises rotation against in-flight decisions within this process. The decision
# conflict check itself holds a file lock (audit.writer.append_unless_conflict), so
# it is also safe across processes.
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
