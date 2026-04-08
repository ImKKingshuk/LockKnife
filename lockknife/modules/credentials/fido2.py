from __future__ import annotations

import dataclasses
import pathlib

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger
from lockknife.core.security import secure_temp_dir
from lockknife.modules.credentials._passkey_exports import safe_passkey_filename, sh_quote

log = get_logger()


@dataclasses.dataclass(frozen=True)
class PasskeyArtifact:
    remote_path: str
    local_path: str | None
    size: int | None


def find_passkey_artifacts(devices: DeviceManager, serial: str, *, limit: int = 200) -> list[str]:
    if not devices.has_root(serial):
        raise DeviceError("Root required to locate passkey artifacts in /data")
    cmd = (
        'su -c "find /data -maxdepth 5 -type f '
        "\\( -iname '*fido*' -o -iname '*passkey*' -o -iname '*credential*' -o -iname '*webauthn*' \\) "
        "2>/dev/null | head -n " + str(int(limit)) + '"'
    )
    raw = devices.shell(serial, cmd, timeout_s=60.0)
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]


def pull_passkey_artifacts(
    devices: DeviceManager,
    serial: str,
    *,
    output_dir: pathlib.Path,
    limit: int = 200,
) -> list[PasskeyArtifact]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = find_passkey_artifacts(devices, serial, limit=limit)
    out: list[PasskeyArtifact] = []
    with secure_temp_dir(prefix="lockknife-passkeys-") as d:
        for rp in paths:
            name = safe_passkey_filename(rp)
            tmp_remote = f"/sdcard/lockknife-{name}"
            local_tmp = d / name
            try:
                devices.shell(
                    serial,
                    f'su -c "cp {sh_quote(rp)} {sh_quote(tmp_remote)} 2>/dev/null"',
                    timeout_s=30.0,
                )
                devices.pull(serial, tmp_remote, local_tmp, timeout_s=120.0)
                try:
                    devices.shell(
                        serial, f'su -c "rm -f {sh_quote(tmp_remote)} 2>/dev/null"', timeout_s=10.0
                    )
                except Exception:
                    log.warning(
                        "passkey_cleanup_failed", exc_info=True, serial=serial, remote=tmp_remote
                    )
                final = output_dir / local_tmp.name
                final.write_bytes(local_tmp.read_bytes())
                out.append(
                    PasskeyArtifact(
                        remote_path=rp, local_path=str(final), size=final.stat().st_size
                    )
                )
            except Exception:
                log.warning("passkey_pull_failed", exc_info=True, serial=serial, remote=rp)
                out.append(PasskeyArtifact(remote_path=rp, local_path=None, size=None))
    return out
