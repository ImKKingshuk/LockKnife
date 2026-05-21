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

import base64
import datetime
import hashlib
import hmac
import json
import os
import pathlib
import threading
from dataclasses import asdict, dataclass
from typing import Any

from lockknife.core.exceptions import CustodyConfigError

_lock = threading.Lock()
_entries: list[CustodyEntry] = []
_SEAL_VERSION = "LK-CUSTODY-SEAL-1"
_MIN_SIGNING_KEY_BYTES = 32


@dataclass
class CustodyEntry:
    op: str  # "pull" | "push"
    serial: str  # ADB serial
    remote_path: str
    local_path: str
    sha256: str  # hex digest of the local file after the transfer
    size_bytes: int
    timestamp_utc: str  # ISO-8601


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
        timestamp_utc=datetime.datetime.now(datetime.UTC).isoformat(),
    )
    with _lock:
        _entries.append(entry)

    if os.environ.get("LOCKKNIFE_SIGNING_KEY"):
        seal_artifact(serial=serial, remote_path=remote_path, local_path=local_path)


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
        timestamp_utc=datetime.datetime.now(datetime.UTC).isoformat(),
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


def _resolve_signing_key(signing_key: bytes | None) -> bytes:
    key = signing_key
    if key is None:
        env_key = os.environ.get("LOCKKNIFE_SIGNING_KEY")
        if not env_key:
            raise CustodyConfigError(
                "Custody sealing requires signing_key or LOCKKNIFE_SIGNING_KEY"
            )
        key = env_key.encode("utf-8")
    if not isinstance(key, bytes):
        raise CustodyConfigError("Custody signing key must be bytes")
    if len(key) < _MIN_SIGNING_KEY_BYTES:
        raise CustodyConfigError(
            f"Custody signing key must be at least {_MIN_SIGNING_KEY_BYTES} bytes"
        )
    return key


def _derive_seal_keys(signing_key: bytes) -> tuple[bytes, bytes]:
    hmac_key = hmac.new(signing_key, b"lockknife-custody-hmac-key-v1", hashlib.sha256).digest()
    aes_key = hmac.new(signing_key, b"lockknife-custody-aes-key-v1", hashlib.sha256).digest()
    return hmac_key, aes_key


def seal_artifact(
    *,
    serial: str,
    remote_path: str,
    local_path: pathlib.Path,
    signing_key: bytes | None = None,
) -> pathlib.Path:
    """Seal artifact metadata with versioned HMAC-SHA256 and AES-256-GCM envelope."""
    if not local_path.exists():
        raise OSError(f"Local file does not exist: {local_path}")

    sha256, size = _sha256_file(local_path)
    if sha256 == "unreadable":
        raise OSError(f"Could not read local file: {local_path}")

    resolved_key = _resolve_signing_key(signing_key)
    hmac_key, aes_key = _derive_seal_keys(resolved_key)

    metadata = {
        "seal_version": _SEAL_VERSION,
        "op": "pull",
        "serial": serial,
        "remote_path": remote_path,
        "local_path": str(local_path),
        "sha256": sha256,
        "size_bytes": size,
        "timestamp_utc": datetime.datetime.now(datetime.UTC).isoformat(),
    }

    meta_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

    import lockknife.lockknife_core as lockknife_core

    hmac_sig = lockknife_core.hmac_sha256(hmac_key, meta_json.encode("utf-8"))

    from lockknife.core.security import encrypt_bytes_aes256gcm

    encrypted_bytes = encrypt_bytes_aes256gcm(
        aes_key, meta_json.encode("utf-8"), associated_data=sha256.encode("utf-8")
    )
    envelope_b64 = base64.b64encode(encrypted_bytes).decode("ascii")

    sig_data = {
        "seal_version": _SEAL_VERSION,
        "algorithms": {
            "metadata_signature": "HMAC-SHA256",
            "metadata_envelope": "AES-256-GCM",
            "key_derivation": "HMAC-SHA256 domain separation",
        },
        "metadata": metadata,
        "hmac_sha256": hmac_sig,
        "aes256gcm_envelope": envelope_b64,
    }

    sig_path = local_path.with_name(local_path.name + ".metadata.json.sig")
    sig_path.write_text(json.dumps(sig_data, indent=2), encoding="utf-8")
    return sig_path


def verify_artifact_seal(
    sig_path: pathlib.Path,
    signing_key: bytes | None = None,
) -> dict[str, Any]:
    """Verifies SHA-256 hash of file, validates HMAC-SHA256 signature, and decrypts the GCM envelope."""
    from lockknife.core.exceptions import CustodyTamperError

    if not sig_path.exists():
        raise CustodyTamperError(f"Signature file does not exist: {sig_path}")

    try:
        sig_data = json.loads(sig_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise CustodyTamperError(f"Failed to parse signature file JSON: {e}") from e

    metadata = sig_data.get("metadata")
    hmac_sig = sig_data.get("hmac_sha256")
    envelope_b64 = sig_data.get("aes256gcm_envelope")

    if not isinstance(metadata, dict) or not hmac_sig or not envelope_b64:
        raise CustodyTamperError("Signature file is missing critical fields")
    if sig_data.get("seal_version") != _SEAL_VERSION:
        raise CustodyTamperError("Unsupported custody seal version")
    if metadata.get("seal_version") != _SEAL_VERSION:
        raise CustodyTamperError("Metadata seal version mismatch")

    local_path_str = metadata.get("local_path")
    expected_sha256 = metadata.get("sha256")

    if not local_path_str or not expected_sha256:
        raise CustodyTamperError("Metadata is missing file path or SHA-256 hash")

    # Locate target file
    target_path = pathlib.Path(local_path_str)
    if not target_path.exists():
        # Try relative to the directory of the signature file
        target_path = sig_path.parent / target_path.name
        if not target_path.exists():
            raise CustodyTamperError(f"Target evidence file not found: {local_path_str}")

    # 1. Compute current hash and verify file integrity
    current_sha256, current_size = _sha256_file(target_path)
    if current_sha256 != expected_sha256:
        raise CustodyTamperError(
            f"Evidence file content tampered! Hash mismatch: expected {expected_sha256}, got {current_sha256}"
        )

    resolved_key = _resolve_signing_key(signing_key)
    hmac_key, aes_key = _derive_seal_keys(resolved_key)

    meta_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
    import lockknife.lockknife_core as lockknife_core

    try:
        calculated_hmac = lockknife_core.hmac_sha256(hmac_key, meta_json.encode("utf-8"))
    except Exception as e:
        raise CustodyTamperError(f"HMAC calculation failed: {e}") from e

    if not hmac.compare_digest(calculated_hmac, str(hmac_sig)):
        raise CustodyTamperError("Metadata signature validation failed! HMAC signature mismatch")

    from lockknife.core.security import decrypt_bytes_aes256gcm

    try:
        encrypted_bytes = base64.b64decode(envelope_b64.encode("ascii"), validate=True)
        decrypted_bytes = decrypt_bytes_aes256gcm(
            aes_key, encrypted_bytes, associated_data=expected_sha256.encode("utf-8")
        )
        decrypted_json = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception as e:
        raise CustodyTamperError(f"AES-256-GCM envelope verification failed: {e}") from e

    # Assert that decrypted metadata matches plaintext metadata
    if decrypted_json != metadata:
        raise CustodyTamperError("Decrypted envelope metadata mismatch with plaintext metadata")

    return {
        "status": "verified",
        "metadata": metadata,
    }
