from __future__ import annotations

import json
import pathlib
import shlex
import time

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.progress import ProgressCallback, emit_progress
from lockknife.core.security import generate_aes256gcm_key, secure_temp_dir


def _validate_snapshot_path(path: str) -> str:
    value = path.strip()
    if not value:
        raise DeviceError("Snapshot paths must be non-empty")
    if any(ch in value for ch in ("\x00", "\n", "\r")):
        raise DeviceError("Snapshot paths contain unsafe control characters")
    if value.startswith("-"):
        raise DeviceError("Snapshot paths cannot start with '-'")
    pure = pathlib.PurePosixPath(value)
    if not pure.is_absolute():
        raise DeviceError("Snapshot paths must be absolute device paths")
    if ".." in pure.parts:
        raise DeviceError("Snapshot paths cannot contain '..'")
    return value


def create_snapshot(
    devices: DeviceManager,
    serial: str,
    *,
    output_path: pathlib.Path,
    paths: list[str] | None = None,
    full: bool = False,
    encrypt: bool = False,
    progress_callback: ProgressCallback | None = None,
) -> pathlib.Path:
    if not devices.has_root(serial):
        raise DeviceError("Root required to create device snapshot")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with secure_temp_dir(prefix="lockknife-snapshot-") as d:
        remote_tar = "/sdcard/lockknife-snapshot.tar"
        selected = paths or []
        if full:
            selected = ["/data/system", "/data/data"]
        if not selected:
            raise DeviceError("No paths selected for snapshot")

        validated = [_validate_snapshot_path(p) for p in selected]
        emit_progress(
            progress_callback,
            operation="forensics.snapshot",
            step="validate",
            message="Validated snapshot inputs",
            current=1,
            total=5,
            metadata={"path_count": len(validated), "encrypted": encrypt},
        )
        joined = " ".join(shlex.quote(p) for p in validated)
        cmd = f'su -c "tar -cf {shlex.quote(remote_tar)} -- {joined} 2>/dev/null"'
        emit_progress(
            progress_callback,
            operation="forensics.snapshot",
            step="device-archive",
            message="Creating device-side snapshot archive",
            current=2,
            total=5,
            metadata={"remote_path": remote_tar},
        )
        devices.shell(serial, cmd, timeout_s=600.0)

        local_tar = d / "snapshot.tar"
        emit_progress(
            progress_callback,
            operation="forensics.snapshot",
            step="pull",
            message="Pulling snapshot archive from device",
            current=3,
            total=5,
            metadata={"remote_path": remote_tar, "output_path": str(output_path)},
        )
        devices.pull(serial, remote_tar, local_tar, timeout_s=600.0)
        try:
            emit_progress(
                progress_callback,
                operation="forensics.snapshot",
                step="cleanup",
                message="Removing temporary snapshot archive from device",
                current=4,
                total=5,
                metadata={"remote_path": remote_tar},
            )
            devices.shell(serial, f'su -c "rm -f {shlex.quote(remote_tar)}"', timeout_s=30.0)
        except DeviceError:
            pass

        meta = {
            "serial": serial,
            "created_at": time.time(),
            "full": full,
            "paths": validated,
            "encrypted": encrypt,
        }
        meta_path = output_path.with_suffix(output_path.suffix + ".meta.json")
        meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")

        if not encrypt:
            output_path.write_bytes(local_tar.read_bytes())
            emit_progress(
                progress_callback,
                operation="forensics.snapshot",
                step="complete",
                message="Snapshot completed",
                current=5,
                total=5,
                metadata={"output_path": str(output_path)},
            )
            return output_path

        from lockknife.core.security import encrypt_file

        key = generate_aes256gcm_key()
        key_path = output_path.with_suffix(output_path.suffix + ".key")
        key_path.write_bytes(key)
        emit_progress(
            progress_callback,
            operation="forensics.snapshot",
            step="encrypt",
            message="Encrypting snapshot archive",
            current=5,
            total=5,
            metadata={"output_path": str(output_path)},
        )
        encrypted_path = encrypt_file(
            local_tar, key, out_path=output_path.with_suffix(output_path.suffix + ".lkenc")
        )
        return encrypted_path
