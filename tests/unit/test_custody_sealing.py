from __future__ import annotations

import base64
import json
import pathlib

import pytest

from lockknife.core.custody import (
    seal_artifact,
    verify_artifact_seal,
)
from lockknife.core.exceptions import CustodyTamperError


def test_custody_sealing_roundtrip(tmp_path: pathlib.Path) -> None:
    # 1. Create a dummy artifact file
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("Confidential Forensic Evidence Content", encoding="utf-8")

    # 2. Seal the artifact
    signing_key = b"very-secure-signing-key-123456789"
    sig_path = seal_artifact(
        serial="device123",
        remote_path="/data/data/com.app/files/evidence.txt",
        local_path=artifact,
        signing_key=signing_key,
    )

    assert sig_path.exists()
    assert sig_path.name == "evidence.txt.metadata.json.sig"

    # Check contents
    sig_content = json.loads(sig_path.read_text(encoding="utf-8"))
    assert "metadata" in sig_content
    assert "hmac_sha256" in sig_content
    assert "aes256gcm_envelope" in sig_content

    # 3. Verify the seal
    res = verify_artifact_seal(sig_path, signing_key=signing_key)
    assert res["status"] == "verified"
    assert res["metadata"]["serial"] == "device123"
    assert res["metadata"]["remote_path"] == "/data/data/com.app/files/evidence.txt"


def test_custody_sealing_tamper_file(tmp_path: pathlib.Path) -> None:
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("Confidential Forensic Evidence Content", encoding="utf-8")

    signing_key = b"very-secure-signing-key-123456789"
    sig_path = seal_artifact(
        serial="device123",
        remote_path="/data/data/com.app/files/evidence.txt",
        local_path=artifact,
        signing_key=signing_key,
    )

    # Tamper with the artifact content
    artifact.write_text("Confidential Forensic Evidence Content - TAMPERED", encoding="utf-8")

    with pytest.raises(CustodyTamperError) as exc_info:
        verify_artifact_seal(sig_path, signing_key=signing_key)
    assert "content tampered" in str(exc_info.value).lower()


def test_custody_sealing_tamper_signature_fields(tmp_path: pathlib.Path) -> None:
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("Confidential Forensic Evidence Content", encoding="utf-8")

    signing_key = b"very-secure-signing-key-123456789"
    sig_path = seal_artifact(
        serial="device123",
        remote_path="/data/data/com.app/files/evidence.txt",
        local_path=artifact,
        signing_key=signing_key,
    )

    # Tamper with the HMAC signature in the signature file
    sig_content = json.loads(sig_path.read_text(encoding="utf-8"))
    sig_content["hmac_sha256"] = "f" * 64
    sig_path.write_text(json.dumps(sig_content), encoding="utf-8")

    with pytest.raises(CustodyTamperError) as exc_info:
        verify_artifact_seal(sig_path, signing_key=signing_key)
    assert "signature validation failed" in str(exc_info.value).lower()


def test_custody_sealing_tamper_envelope(tmp_path: pathlib.Path) -> None:
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("Confidential Forensic Evidence Content", encoding="utf-8")

    signing_key = b"very-secure-signing-key-123456789"
    sig_path = seal_artifact(
        serial="device123",
        remote_path="/data/data/com.app/files/evidence.txt",
        local_path=artifact,
        signing_key=signing_key,
    )

    # Tamper with the GCM envelope
    sig_content = json.loads(sig_path.read_text(encoding="utf-8"))
    # Base64 decode, flip a bit, base64 encode
    envelope_bytes = bytearray(base64.b64decode(sig_content["aes256gcm_envelope"]))
    envelope_bytes[0] ^= 0x01
    sig_content["aes256gcm_envelope"] = base64.b64encode(envelope_bytes).decode("ascii")
    sig_path.write_text(json.dumps(sig_content), encoding="utf-8")

    with pytest.raises(CustodyTamperError) as exc_info:
        verify_artifact_seal(sig_path, signing_key=signing_key)
    assert "envelope verification failed" in str(exc_info.value).lower()
