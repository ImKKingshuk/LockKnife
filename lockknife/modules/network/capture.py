from __future__ import annotations

import dataclasses
import pathlib
import re
import shlex
import time

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger
from lockknife.core.progress import ProgressCallback, emit_progress
from lockknife.core.security import secure_temp_dir

log = get_logger()
_RE_IFACE = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")


def _validate_iface(iface: str) -> str:
    value = iface.strip()
    if not value:
        raise ValueError("iface must be non-empty")
    if not _RE_IFACE.match(value):
        raise ValueError("iface contains unsafe characters")
    return value


@dataclasses.dataclass(frozen=True)
class CaptureResult:
    serial: str
    remote_path: str
    local_path: str
    duration_s: float
    started_at: float
    finished_at: float


def capture_pcap(
    devices: DeviceManager,
    serial: str,
    *,
    output_path: pathlib.Path,
    duration_s: float = 30.0,
    iface: str = "any",
    snaplen: int = 0,
    progress_callback: ProgressCallback | None = None,
) -> CaptureResult:
    if duration_s <= 0:
        raise ValueError("duration_s must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required for tcpdump capture")
    iface_name = _validate_iface(iface)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    remote = f"/sdcard/lockknife-capture-{int(time.time())}.pcap"
    sl = int(snaplen)
    if sl < 0 or sl > 65535:
        raise ValueError("snaplen must be between 0 and 65535")
    sl_arg = "-s 0" if sl <= 0 else f"-s {sl}"
    dur = int(duration_s)
    started = time.time()
    emit_progress(
        progress_callback,
        operation="network.capture",
        step="start",
        message="Starting device packet capture",
        current=1,
        total=4,
        metadata={"interface": iface_name, "duration_s": float(duration_s), "snaplen": sl},
    )
    cmd = (
        "su -c \"sh -c '"
        f"tcpdump -i {shlex.quote(iface_name)} {sl_arg} -w {shlex.quote(remote)} >/dev/null 2>&1 & "
        "pid=$!; "
        f"sleep {dur}; "
        "kill -INT $pid >/dev/null 2>&1; "
        "wait $pid >/dev/null 2>&1; "
        "'\""
    )
    devices.shell(serial, cmd, timeout_s=max(30.0, duration_s + 30.0))

    with secure_temp_dir(prefix="lockknife-netcap-") as d:
        local = d / pathlib.PurePosixPath(remote).name
        emit_progress(
            progress_callback,
            operation="network.capture",
            step="pull",
            message="Pulling pcap from device",
            current=2,
            total=4,
            metadata={"remote_path": remote, "output_path": str(output_path)},
        )
        devices.pull(serial, remote, local, timeout_s=max(60.0, duration_s + 60.0))
        try:
            emit_progress(
                progress_callback,
                operation="network.capture",
                step="cleanup",
                message="Removing temporary pcap from device",
                current=3,
                total=4,
                metadata={"remote_path": remote},
            )
            devices.shell(
                serial, f'su -c "rm -f {shlex.quote(remote)} 2>/dev/null"', timeout_s=10.0
            )
        except DeviceError:
            log.warning("pcap_cleanup_failed", exc_info=True, serial=serial, remote=remote)
        output_path.write_bytes(local.read_bytes())

    finished = time.time()
    emit_progress(
        progress_callback,
        operation="network.capture",
        step="complete",
        message="Packet capture completed",
        current=4,
        total=4,
        metadata={"output_path": str(output_path)},
    )
    return CaptureResult(
        serial=serial,
        remote_path=remote,
        local_path=str(output_path),
        duration_s=float(duration_s),
        started_at=started,
        finished_at=finished,
    )
