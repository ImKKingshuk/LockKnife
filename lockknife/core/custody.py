from __future__ import annotations

"""Chain-of-custody logging for forensic file operations.

Every pull / push via ADB is automatically logged here with a SHA-256 hash,
timestamps, and source location so the log can serve as an audit trail when
presenting evidence.

Usage::

    from lockknife.core.custody import log_pull, log_push, dump_log

    log_pull(serial="abc123", remote_path="/data/data/foo.db", local_path=Path("/tmp/foo.db"))
    print(dump_log())   # JSON array
"""

import datetime
import hashlib
import json
import pathlib
import threading
from dataclasses import asdict, dataclass, field

_lock = threading.Lock()
_entries: list["CustodyEntry"] = []


@dataclass
class CustodyEntry:
    op: str                      # "pull" | "push"
    serial: str                  # ADB serial
    remote_path: str
    local_path: str
    sha256: str                  # hex digest of the local file after the transfer
    size_bytes: int
    timestamp_utc: str           # ISO-8601


def _sha256_file(path: pathlib.Path) -> tuple[str, int]:
    """Return (hex_digest, size_bytes) for *path*."""
    h = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
                total += len(chunk)
    except OSError:
        return "unreadable", 0
    return h.hexdigest(), total


def log_pull(*, serial: str, remote_path: str, local_path: pathlib.Path) -> None:
    """Record a completed ADB pull operation into the custody log."""
    sha256, size = _sha256_file(local_path)
    entry = CustodyEntry(
        op="pull",
        serial=serial,
        remote_path=remote_path,
        local_path=str(local_path),
        sha256=sha256,
        size_bytes=size,
        timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
    with _lock:
        _entries.append(entry)


def log_push(*, serial: str, local_path: pathlib.Path, remote_path: str) -> None:
    """Record a completed ADB push operation into the custody log."""
    sha256, size = _sha256_file(local_path)
    entry = CustodyEntry(
        op="push",
        serial=serial,
        remote_path=remote_path,
        local_path=str(local_path),
        sha256=sha256,
        size_bytes=size,
        timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
    with _lock:
        _entries.append(entry)


def dump_log() -> str:
    """Return the full custody log as a JSON array string."""
    with _lock:
        data = [asdict(e) for e in _entries]
    return json.dumps(data, indent=2)


def list_entries() -> list[CustodyEntry]:
    """Return the custody log as dataclass entries."""
    with _lock:
        return list(_entries)


def save_log(path: pathlib.Path) -> None:
    """Write the custody log to *path* as JSON."""
    path.write_text(dump_log(), encoding="utf-8")


def clear_log() -> None:
    """Reset the in-memory custody log (useful in tests)."""
    with _lock:
        _entries.clear()
