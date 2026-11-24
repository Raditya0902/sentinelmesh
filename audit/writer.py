"""Single Python-side writer for the shared audit log.

The Go proxy appends to the same JSONL file with O_APPEND. Python writers take an
exclusive flock around each append so concurrent API workers never interleave
partial lines with each other, and each entry is emitted as one write() call so it
lands atomically relative to the proxy's appends.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import shutil
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

DEFAULT_AUDIT_LOG_PATH = "logs/audit.jsonl"
ROTATION_RULE_NAME = "audit_rotated"


class AuditWriteError(RuntimeError):
    """Raised in strict mode when an audit entry cannot be persisted."""


def default_audit_path(env: Mapping[str, str] | None = None) -> Path:
    source = os.environ if env is None else env
    return Path(source.get("AUDIT_LOG_PATH", DEFAULT_AUDIT_LOG_PATH))


def is_strict(env: Mapping[str, str] | None = None) -> bool:
    """Strict (fail-closed) unless explicitly disabled or running in demo mode."""
    source = os.environ if env is None else env
    explicit = source.get("AUDIT_STRICT")
    if explicit is not None:
        return explicit == "1"
    return source.get("SENTINEL_DEMO_MODE") != "1"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _locked(path: Path, mode: str) -> Iterator:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open(mode) as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield fh
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def _write_line(fh, entry: Mapping) -> None:
    fh.write(json.dumps(dict(entry)) + "\n")
    fh.flush()


def append_entry(
    entry: Mapping,
    path: Path | None = None,
    strict: bool | None = None,
) -> None:
    """Append one audit entry. Raises AuditWriteError on failure when strict."""
    target = path if path is not None else default_audit_path()
    record = {"timestamp": utc_now_iso(), **entry}
    try:
        with _locked(target, "a") as fh:
            _write_line(fh, record)
    except OSError as exc:
        logger.error("audit write failed path=%s rule=%s: %s", target, entry.get("rule_name"), exc)
        if is_strict() if strict is None else strict:
            raise AuditWriteError(f"audit write failed: {exc}") from exc


def _parse_rows(lines: list[str]) -> list[dict]:
    rows = []
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def append_unless_conflict(
    path: Path,
    entry: Mapping,
    find_conflict: Callable[[list[dict]], Optional[dict]],
) -> Optional[dict]:
    """Append ``entry`` unless ``find_conflict(existing_rows)`` returns a row.

    The read and the append happen under one exclusive file lock, so two writers
    (threads or processes) can never both pass the check. Returns the conflicting
    row, or None after writing. Always strict: raises AuditWriteError on failure.
    """
    record = {"timestamp": utc_now_iso(), **entry}
    try:
        with _locked(path, "a+") as fh:
            fh.seek(0)
            conflict = find_conflict(_parse_rows(fh.readlines()))
            if conflict is not None:
                return conflict
            _write_line(fh, record)
    except OSError as exc:
        logger.error("decision write failed path=%s: %s", path, exc)
        raise AuditWriteError(f"audit write failed: {exc}") from exc
    return None


def _archive_copy(path: Path, stamp: str) -> Path:
    archive = path.with_name(f"{path.stem}-{stamp}{path.suffix}")
    shutil.copyfile(path, archive)
    return archive


def rotate_audit_log(audit_path: Path, decisions_path: Path, rotated_by: str) -> Path:
    """Archive the audit log (and review decisions) and start fresh files.

    Uses copy-then-truncate rather than rename: the Go proxy keeps the audit file
    open with O_APPEND, so a rename would silently redirect its writes into the
    archive. Lines the proxy appends between the copy and the truncate are lost;
    that window is a few milliseconds and is documented as a known limitation.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    with _locked(audit_path, "a+") as fh:
        archive = _archive_copy(audit_path, stamp)
        fh.truncate(0)
        _write_line(fh, {
            "timestamp": utc_now_iso(),
            "request_id": f"rotate-{stamp}",
            "direction": "ingress",
            "action": "LOG",
            "rule_name": ROTATION_RULE_NAME,
            "agent_id": "api",
            "role": rotated_by,
            "archive": archive.name,
        })

    if decisions_path.exists():
        with _locked(decisions_path, "a+") as fh:
            _archive_copy(decisions_path, stamp)
            fh.truncate(0)

    logger.info("audit log rotated by role=%s archive=%s", rotated_by, archive)
    return archive
