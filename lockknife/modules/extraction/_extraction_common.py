from __future__ import annotations

import base64
import binascii
import os
import pathlib
import re
import tempfile
from typing import Any

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import LockKnifeError
from lockknife.core.logging import get_logger

log = get_logger()

DEVICE_IO_ERRORS: tuple[type[BaseException], ...] = (
    LockKnifeError,
    OSError,
    RuntimeError,
    ValueError,
)


def sh_quote(s: str) -> str:
    """Safely quote a string for use in POSIX shell command strings."""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def content_query_command(
    uri: str, projection: tuple[str, ...], *, sort: str | None = None, root: bool = True
) -> str:
    command = f"content query --uri {sh_quote(uri)} --projection {sh_quote(':'.join(projection))}"
    if sort:
        command += " --sort " + sh_quote(sort)
    return "su -c " + sh_quote(command) if root else command


def try_root_staging_pull(
    devices: DeviceManager,
    serial: str,
    remote: str,
    local: pathlib.Path,
    *,
    timeout_s: float = 90.0,
) -> bool:
    """Acquire a file without copying privileged evidence to shared device storage.

    Each attempt uses a fresh private host file. Root fallback reads bounded
    base64 over ADB shell; it never stages credentials in /sdcard.
    """
    local.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".lockknife-pull-", dir=local.parent)
    os.close(fd)
    attempt = pathlib.Path(name)
    try:
        try:
            devices.pull(serial, remote, attempt, timeout_s=timeout_s)
            pulled = attempt.is_file() and attempt.stat().st_size > 0
        except DEVICE_IO_ERRORS:
            pulled = False
        if not pulled:
            if not devices.has_root(serial):
                return False
            quoted = sh_quote(remote)
            max_bytes = 64 * 1024 * 1024
            command = (
                f"test -f {quoted} && size=$(stat -c %s {quoted}) && "
                f'test "$size" -gt 0 && test "$size" -le {max_bytes} && '
                f"base64 {quoted}"
            )
            encoded = devices.shell(serial, "su -c " + sh_quote(command), timeout_s=timeout_s)
            if len(encoded) > max_bytes * 2:
                return False
            content = base64.b64decode("".join(encoded.split()), validate=True)
            if not content or len(content) > max_bytes:
                return False
            attempt.write_bytes(content)
        os.chmod(attempt, 0o600)
        attempt.replace(local)
        return True
    except (*DEVICE_IO_ERRORS, binascii.Error):
        log.warning("root_read_failed", exc_info=True, serial=serial, remote=remote)
        return False
    finally:
        attempt.unlink(missing_ok=True)


def parse_content_query_rows(raw: str) -> list[dict[str, str]]:
    """Parse output from Android 'content query --uri ...' shell commands.

    Android content query outputs lines beginning with 'Row: <index> ' followed
    by comma-delimited key=value pairs.
    """
    if not raw.strip():
        return []

    # Split rows on 'Row: <N> ' markers
    chunks = re.split(r"(?m)^Row:\s*\d+\s*", raw)
    rows: list[dict[str, str]] = []

    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        entry: dict[str, str] = {}
        # Parse key=value pairs, allowing commas inside values unless followed by another key=
        pattern = re.compile(r"([a-zA-Z0-9_]+)=(.*?)(?:,\s+(?=[a-zA-Z0-9_]+=)|\Z)", re.DOTALL)
        for m in pattern.finditer(chunk):
            k = m.group(1).strip()
            v = m.group(2).strip()
            # If value is 'null', normalize to None or empty
            if v == "NULL" or v == "null":
                entry[k] = ""
            else:
                entry[k] = v
        if entry:
            rows.append(entry)

    return rows
