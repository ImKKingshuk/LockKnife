from __future__ import annotations

import base64
import dataclasses
import pathlib
import sqlite3

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger
from lockknife.core.security import secure_temp_dir
from lockknife.modules.credentials._passkey_exports import safe_passkey_filename, sh_quote
from lockknife.modules.extraction._extraction_common import try_root_staging_pull

log = get_logger()

PASSKEY_CANDIDATE_PATHS: tuple[str, ...] = (
    "/data/user/0/com.google.android.gms/databases/fido2.db",
    "/data/user/0/com.google.android.gms/databases/identity_fido_credentials.db",
    "/data/user/0/com.google.android.gms/databases/passkeys.db",
    "/data/data/com.google.android.gms/databases/fido2.db",
    "/data/data/com.google.android.gms/databases/identity_fido_credentials.db",
    "/data/data/com.google.android.gms/databases/passkeys.db",
    "/data/system_ce/0/credential_provider.db",
    "/data/user/0/com.android.chrome/app_chrome/Default/Web Data",
    "/data/data/com.android.chrome/app_chrome/Default/Web Data",
)


@dataclasses.dataclass(frozen=True)
class PasskeyArtifact:
    remote_path: str
    local_path: str | None
    size: int | None


@dataclasses.dataclass(frozen=True)
class PasskeyRecord:
    rp_id: str
    user_name: str | None
    user_display_name: str | None
    credential_id: str
    source_file: str
    created_epoch: int | None = None
    last_used_epoch: int | None = None


def parse_passkey_database(path: pathlib.Path) -> list[PasskeyRecord]:
    """Parse SQLite database containing WebAuthn, FIDO2, or Passkey credential tables."""
    if not path.is_file():
        return []
    records: list[PasskeyRecord] = []
    uri = path.resolve().as_uri() + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return []

    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        tables = [
            row["name"]
            for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        ]

        for tbl in (
            "fido_credentials",
            "credentials",
            "public_key_credentials",
            "passkeys",
            "webauthn",
        ):
            if tbl not in tables:
                continue
            cols_info = cur.execute(f'PRAGMA table_info("{tbl}")').fetchall()
            cols = {row["name"].lower() for row in cols_info}
            rp_col = next(
                (c for c in ("rp_id", "relying_party_id", "rpid") if c.lower() in cols),
                None,
            )
            user_col = next(
                (
                    c
                    for c in ("user_name", "username", "user_id", "userhandle", "user_handle")
                    if c.lower() in cols
                ),
                None,
            )
            display_col = next(
                (
                    c
                    for c in ("display_name", "user_display_name", "displayname")
                    if c.lower() in cols
                ),
                None,
            )
            cred_id_col = next(
                (c for c in ("credential_id", "id", "credentialid") if c.lower() in cols),
                None,
            )
            created_col = next(
                (
                    c
                    for c in ("created_time", "date_created", "creation_time", "created_epoch")
                    if c.lower() in cols
                ),
                None,
            )
            used_col = next(
                (
                    c
                    for c in ("last_used_time", "last_used_epoch", "last_use_time")
                    if c.lower() in cols
                ),
                None,
            )

            if not rp_col or not cred_id_col:
                continue

            query = f'SELECT * FROM "{tbl}"'
            for r in cur.execute(query + " LIMIT 100000"):
                rp_val = str(r[rp_col] or "").strip()
                raw_id = r[cred_id_col]
                cred_val = (
                    base64.urlsafe_b64encode(raw_id).decode("ascii").rstrip("=")
                    if isinstance(raw_id, bytes)
                    else str(raw_id or "").strip()
                )
                if not rp_val or not cred_val:
                    continue
                user_val = str(r[user_col]) if user_col and r[user_col] is not None else None
                disp_val = (
                    str(r[display_col]) if display_col and r[display_col] is not None else None
                )
                c_epoch = None
                if created_col and r[created_col] is not None:
                    try:
                        c_epoch = int(r[created_col])
                    except (ValueError, TypeError):
                        pass
                u_epoch = None
                if used_col and r[used_col] is not None:
                    try:
                        u_epoch = int(r[used_col])
                    except (ValueError, TypeError):
                        pass

                records.append(
                    PasskeyRecord(
                        rp_id=rp_val,
                        user_name=user_val,
                        user_display_name=disp_val,
                        credential_id=cred_val,
                        source_file=str(path),
                        created_epoch=c_epoch,
                        last_used_epoch=u_epoch,
                    )
                )

        return records
    except Exception as e:
        log.warning("passkey_db_parse_failed", exc_info=True, path=str(path), error=str(e))
        return []
    finally:
        conn.close()


def find_passkey_artifacts(devices: DeviceManager, serial: str, *, limit: int = 200) -> list[str]:
    """Locate FIDO2 and passkey artifact databases on device, checking targeted candidate paths first."""
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to locate passkey artifacts in /data")

    found: list[str] = []
    # Fast path: test known targeted database paths
    for cp in PASSKEY_CANDIDATE_PATHS:
        try:
            out = devices.shell(
                serial,
                f'su -c "test -f {sh_quote(cp)} && echo exists || true"',
                timeout_s=5.0,
            ).strip()
            if "exists" in out and cp not in found:
                found.append(cp)
        except Exception:
            pass

    if found:
        return found[:limit]

    cmd = (
        'su -c "find /data/user/0 /data/system -maxdepth 4 -type f '
        "\\( -iname '*fido*' -o -iname '*passkey*' -o -iname '*credential*' -o -iname '*webauthn*' \\) "
        "2>/dev/null | head -n " + str(int(limit)) + '"'
    )
    try:
        raw = devices.shell(serial, cmd, timeout_s=30.0)
        return [ln.strip() for ln in raw.splitlines() if ln.strip()]
    except Exception:
        return []


def pull_passkey_artifacts(
    devices: DeviceManager,
    serial: str,
    *,
    output_dir: pathlib.Path,
    limit: int = 200,
) -> list[PasskeyArtifact]:
    """Acquire passkey databases without shared-storage staging."""
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = find_passkey_artifacts(devices, serial, limit=limit)
    out: list[PasskeyArtifact] = []
    with secure_temp_dir(prefix="lockknife-passkeys-") as d:
        for rp in paths:
            name = safe_passkey_filename(rp)
            local_tmp = d / name
            try:
                if not try_root_staging_pull(devices, serial, rp, local_tmp, timeout_s=120.0):
                    raise DeviceError("Passkey artifact could not be acquired")
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


def extract_passkey_records(
    devices: DeviceManager,
    serial: str,
    *,
    output_dir: pathlib.Path | None = None,
    limit: int = 200,
) -> list[PasskeyRecord]:
    """Pull passkey databases and parse them into structured PasskeyRecord objects."""
    records: list[PasskeyRecord] = []
    with secure_temp_dir(prefix="lockknife-passkey-records-") as temp_dir:
        target_dir = output_dir if output_dir is not None else temp_dir
        artifacts = pull_passkey_artifacts(devices, serial, output_dir=target_dir, limit=limit)
        for art in artifacts:
            if art.local_path and pathlib.Path(art.local_path).is_file():
                parsed = parse_passkey_database(pathlib.Path(art.local_path))
                records.extend(parsed)
    return records
