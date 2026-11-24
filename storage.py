"""SQLite connections for paused-run state (LangGraph checkpoints + review map).

Checkpoints hold full run state (task, document text, extraction output), so the
file is created owner-only and deleted rows are zeroed (``secure_delete``). WAL lets
the checkpointer and the review map, which share the file, read while the other
writes; ``busy_timeout`` waits out short write locks instead of failing.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

MEMORY_DB = ":memory:"
BUSY_TIMEOUT_MS = 10_000
OWNER_ONLY_FILE = 0o600
OWNER_ONLY_DIR = 0o700


def _prepare_path(db_path: str) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=OWNER_ONLY_DIR)
    if not path.exists():
        # Create it owner-only before SQLite opens it with the process umask.
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, OWNER_ONLY_FILE))
    os.chmod(path, OWNER_ONLY_FILE)


def connect(db_path: str, isolation_level: str | None = "") -> sqlite3.Connection:
    """Open a thread-shareable connection (callers serialise access with a lock)."""
    if db_path != MEMORY_DB:
        _prepare_path(db_path)
    conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=isolation_level,
                           timeout=BUSY_TIMEOUT_MS / 1000)
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA secure_delete = ON")
    if db_path != MEMORY_DB:
        conn.execute("PRAGMA journal_mode = WAL")
    return conn
