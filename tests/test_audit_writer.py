import json

import pytest

from audit.writer import AuditWriteError, append_entry, is_strict, rotate_audit_log


def _read_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_append_entry_writes_one_json_line(tmp_path):
    log = tmp_path / "audit.jsonl"

    append_entry({"action": "DENY", "rule_name": "x"}, path=log)
    append_entry({"action": "DENY", "rule_name": "y"}, path=log)

    entries = _read_lines(log)
    assert [e["rule_name"] for e in entries] == ["x", "y"]


def test_append_entry_creates_parent_directory(tmp_path):
    log = tmp_path / "nested" / "audit.jsonl"

    append_entry({"action": "DENY"}, path=log)

    assert log.exists()


def test_append_entry_raises_in_strict_mode_when_write_fails(tmp_path):
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("")
    log = blocker / "audit.jsonl"  # parent is a file → OSError

    with pytest.raises(AuditWriteError):
        append_entry({"action": "DENY"}, path=log, strict=True)


def test_append_entry_logs_but_does_not_raise_when_not_strict(tmp_path, caplog):
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("")
    log = blocker / "audit.jsonl"

    append_entry({"action": "DENY"}, path=log, strict=False)

    assert "audit write failed" in caplog.text


@pytest.mark.parametrize(
    "env, expected",
    [
        ({}, True),
        ({"SENTINEL_DEMO_MODE": "1"}, False),
        ({"SENTINEL_DEMO_MODE": "1", "AUDIT_STRICT": "1"}, True),
        ({"AUDIT_STRICT": "0"}, False),
    ],
)
def test_is_strict_defaults_on_outside_demo_mode(env, expected):
    assert is_strict(env) is expected


def test_rotate_archives_instead_of_deleting(tmp_path):
    log = tmp_path / "audit.jsonl"
    decisions = tmp_path / "review_decisions.jsonl"
    append_entry({"action": "DENY", "request_id": "req-1"}, path=log)
    append_entry({"request_id": "req-1", "decision": "approve"}, path=decisions)

    archive = rotate_audit_log(log, decisions, rotated_by="admin")

    archived = _read_lines(archive)
    assert archived[0]["request_id"] == "req-1"
    assert archive.parent == tmp_path
    assert decisions.read_text() == ""
    archived_decisions = list(tmp_path.glob("review_decisions-*.jsonl"))
    assert len(archived_decisions) == 1


def test_rotate_writes_rotation_record_into_fresh_log(tmp_path):
    log = tmp_path / "audit.jsonl"
    append_entry({"action": "DENY"}, path=log)

    archive = rotate_audit_log(log, tmp_path / "review_decisions.jsonl", rotated_by="admin")

    fresh = _read_lines(log)
    assert len(fresh) == 1
    assert fresh[0]["action"] == "LOG"
    assert fresh[0]["rule_name"] == "audit_rotated"
    assert fresh[0]["archive"] == archive.name
    assert fresh[0]["role"] == "admin"


def test_rotate_keeps_same_inode_so_open_appenders_keep_working(tmp_path):
    # The Go proxy holds audit.jsonl open with O_APPEND; renaming would redirect
    # its writes into the archive. Copy-truncate keeps the original inode.
    log = tmp_path / "audit.jsonl"
    append_entry({"action": "DENY"}, path=log)
    inode_before = log.stat().st_ino
    with log.open("a") as long_lived_writer:
        rotate_audit_log(log, tmp_path / "review_decisions.jsonl", rotated_by="admin")
        long_lived_writer.write(json.dumps({"action": "ALLOW"}) + "\n")

    assert log.stat().st_ino == inode_before
    assert [e["action"] for e in _read_lines(log)] == ["LOG", "ALLOW"]
