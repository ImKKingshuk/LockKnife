from __future__ import annotations

import pathlib
import re
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


def try_root_staging_pull(
    devices: DeviceManager,
    serial: str,
    remote: str,
    local: pathlib.Path,
    *,
    timeout_s: float = 90.0,
) -> bool:
    """Pull a privileged file from an Android device, falling back to root

    staging in /sdcard when unprivileged adbd lacks read permission to /data.
    """
    try:
        devices.pull(serial, remote, local, timeout_s=timeout_s)
        if local.exists() and local.stat().st_size > 0:
            return True
    except DEVICE_IO_ERRORS:
        log.debug("direct_pull_failed_fallback_staging", exc_info=True, serial=serial, remote=remote)

    staging_remote = f"/sdcard/lockknife-staging-{local.name}"
    quoted_remote = sh_quote(remote)
    quoted_staging = sh_quote(staging_remote)
    try:
        devices.shell(
            serial,
            f'su -c "cp {quoted_remote} {quoted_staging} 2>/dev/null || cat {quoted_remote} > {quoted_staging} 2>/dev/null"',
            timeout_s=timeout_s,
        )
        devices.pull(serial, staging_remote, local, timeout_s=timeout_s)
    except DEVICE_IO_ERRORS:
        log.warning("root_staging_pull_failed", exc_info=True, serial=serial, remote=remote)
        return False
    finally:
        try:
            devices.shell(serial, f'su -c "rm -f {quoted_staging} 2>/dev/null"', timeout_s=10.0)
        except DEVICE_IO_ERRORS:
            log.warning("root_staging_cleanup_failed", exc_info=True, serial=serial, remote=staging_remote)
    return local.exists() and local.stat().st_size > 0


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
