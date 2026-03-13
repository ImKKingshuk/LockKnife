from __future__ import annotations

import os
import pathlib
import secrets
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.cleanup import register_temp_path, unregister_temp_path


class CryptoError(LockKnifeError):
    pass


@contextmanager
def secure_temp_dir(prefix: str = "lockknife-") -> Iterator[pathlib.Path]:
    with tempfile.TemporaryDirectory(prefix=prefix) as d:
        path = pathlib.Path(d)
        os.chmod(path, 0o700)
        register_temp_path(path)
        try:
            yield path
        finally:
            unregister_temp_path(path)


def secure_delete(path: pathlib.Path, passes: int = 1) -> None:
    """Best-effort secure deletion for regular files.

    Note: SSDs, journaling, and copy-on-write filesystems may retain data despite overwrites.
    """
    if passes < 1:
        raise ValueError("passes must be >= 1")
    if not path.exists():
        return
    if not path.is_file():
        raise ValueError("secure_delete only supports regular files")

    length = path.stat().st_size
    with path.open("r+b") as f:
        for _ in range(passes):
            f.seek(0)
            remaining = length
            while remaining > 0:
                chunk = min(1024 * 1024, remaining)
                f.write(secrets.token_bytes(chunk))
                remaining -= chunk
            f.flush()
            os.fsync(f.fileno())
    path.unlink(missing_ok=True)


def generate_aes256gcm_key() -> bytes:
    return secrets.token_bytes(32)


def encrypt_bytes_aes256gcm(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    try:
        import lockknife.lockknife_core as lockknife_core
    except Exception as e:
        raise CryptoError("lockknife_core extension is not available") from e
    nonce = secrets.token_bytes(12)
    ciphertext = lockknife_core.aes256gcm_encrypt(key, nonce, plaintext, associated_data)
    return b"LK1" + nonce + ciphertext


def decrypt_bytes_aes256gcm(key: bytes, payload: bytes, associated_data: bytes = b"") -> bytes:
    if len(payload) < 3 + 12 or payload[:3] != b"LK1":
        raise CryptoError("Invalid encrypted payload")
    nonce = payload[3:15]
    ciphertext = payload[15:]
    try:
        import lockknife.lockknife_core as lockknife_core
    except Exception as e:
        raise CryptoError("lockknife_core extension is not available") from e
    try:
        return lockknife_core.aes256gcm_decrypt(key, nonce, ciphertext, associated_data)
    except Exception as e:
        raise CryptoError("Decryption failed") from e


def encrypt_file(path: pathlib.Path, key: bytes, out_path: pathlib.Path | None = None) -> pathlib.Path:
    data = path.read_bytes()
    encrypted = encrypt_bytes_aes256gcm(key, data, associated_data=b"lockknife-evidence")
    target = out_path or path.with_suffix(path.suffix + ".lkenc")
    target.write_bytes(encrypted)
    return target


def decrypt_file(path: pathlib.Path, key: bytes, out_path: pathlib.Path | None = None) -> pathlib.Path:
    data = path.read_bytes()
    decrypted = decrypt_bytes_aes256gcm(key, data, associated_data=b"lockknife-evidence")
    target = out_path or path.with_suffix(".dec")
    target.write_bytes(decrypted)
    return target
