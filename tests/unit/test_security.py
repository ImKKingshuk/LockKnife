import os
import pathlib

from lockknife.core.security import (
    decrypt_bytes_aes256gcm,
    encrypt_bytes_aes256gcm,
    generate_aes256gcm_key,
    secure_delete,
    secure_temp_dir,
)


def test_secure_temp_dir_has_private_permissions() -> None:
    with secure_temp_dir() as d:
        mode = os.stat(d).st_mode & 0o777
        assert mode == 0o700


def test_secure_delete_removes_file(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "x.bin"
    p.write_bytes(b"hello")
    secure_delete(p, passes=1)
    assert not p.exists()


def test_encrypt_decrypt_roundtrip() -> None:
    key = generate_aes256gcm_key()
    plaintext = b"evidence"
    payload = encrypt_bytes_aes256gcm(key, plaintext)
    out = decrypt_bytes_aes256gcm(key, payload)
    assert out == plaintext
