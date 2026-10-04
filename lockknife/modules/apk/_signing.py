from __future__ import annotations

import hashlib
import pathlib
from typing import Any

from lockknife.modules.apk._decompile_archive import archive_inventory
from lockknife.modules.apk._decompile_inspection import _apk_method


def _detect_signing_schemes(apk_path: pathlib.Path, inventory: dict[str, Any]) -> dict[str, bool]:
    schemes = {
        "v1": bool(inventory.get("meta_inf_signers")),
        "v2": False,
        "v3": False,
        "v4": False,
    }
    try:
        import struct

        # Read the ZIP tail and signing block metadata without loading the APK.
        with apk_path.open("rb") as handle:
            handle.seek(0, 2)
            file_size = handle.tell()
            tail_size = min(file_size, 65557)
            handle.seek(file_size - tail_size)
            tail = handle.read(tail_size)
            eocd = tail.rfind(b"PK\x05\x06")
            while eocd >= 0:
                if eocd + 22 <= len(tail):
                    comment_len = struct.unpack_from("<H", tail, eocd + 20)[0]
                    if eocd + 22 + comment_len == len(tail):
                        break
                eocd = tail.rfind(b"PK\x05\x06", 0, eocd)
            if eocd < 0:
                return schemes
            disk, cd_disk, disk_entries, entries, cd_size, cd_offset = struct.unpack_from(
                "<HHHHII", tail, eocd + 4
            )
            if (
                disk
                or cd_disk
                or disk_entries != entries
                or cd_offset + cd_size != file_size - tail_size + eocd
                or cd_offset < 32
            ):
                return schemes
            handle.seek(cd_offset - 24)
            footer = handle.read(24)
            if footer[8:] != b"APK Sig Block 42":
                return schemes
            block_size = struct.unpack_from("<Q", footer)[0]
            block_start = cd_offset - 8 - block_size
            if block_size < 24 or block_start < 0:
                return schemes
            handle.seek(block_start)
            if struct.unpack("<Q", handle.read(8))[0] != block_size:
                return schemes
            pos, end = block_start + 8, cd_offset - 24
            detected: set[int] = set()
            while pos < end:
                if end - pos < 12:
                    return schemes
                handle.seek(pos)
                pair_len, sig_id = struct.unpack("<QI", handle.read(12))
                if pair_len < 4 or pair_len > end - pos - 8:
                    return schemes
                detected.add(sig_id)
                pos += 8 + pair_len
            schemes["v2"] = 0x7109871A in detected
            schemes["v3"] = bool(detected & {0xF05368C0, 0x1B93AD61})
    except (OSError, ValueError, struct.error):
        pass
    return schemes


def signing_summary(apk_obj: Any, apk_path: pathlib.Path) -> dict[str, Any]:
    certificates = [
        certificate_payload(cert) for cert in (_apk_method(apk_obj, "get_certificates", []) or [])
    ]
    inventory = archive_inventory(apk_path)
    if apk_obj is not None:
        schemes = {
            "v1": bool(_apk_method(apk_obj, "is_signed_v1", False)),
            "v2": bool(_apk_method(apk_obj, "is_signed_v2", False)),
            "v3": bool(_apk_method(apk_obj, "is_signed_v3", False)),
            "v4": bool(_apk_method(apk_obj, "is_signed_v4", False)),
        }
    else:
        schemes = _detect_signing_schemes(apk_path, inventory)
    certificate_count = len(certificates)
    signature_algorithms = sorted(
        {
            str(item.get("signature_algorithm"))
            for item in certificates
            if item.get("signature_algorithm")
        }
    )
    has_debug_or_test = any(item.get("is_debug_or_test") for item in certificates)
    if not certificates and inventory.get("meta_inf_signers"):
        has_debug_or_test = any(
            any(token in signer.lower() for token in ["test", "debug", "devkey"])
            for signer in inventory["meta_inf_signers"]
        )
    lineage = [
        {
            "index": index + 1,
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "sha256": cert.get("sha256"),
            "signature_algorithm": cert.get("signature_algorithm"),
            "is_debug_or_test": cert.get("is_debug_or_test"),
        }
        for index, cert in enumerate(certificates)
    ]
    findings = _strict_signing_findings(
        schemes=schemes,
        certificates=certificates,
        meta_inf_signers=list(inventory.get("meta_inf_signers") or []),
        signature_algorithms=signature_algorithms,
        has_debug_or_test=has_debug_or_test,
    )
    severities = [str(item.get("severity") or "info") for item in findings]
    status = "fail" if "fail" in severities else ("warn" if "warn" in severities else "pass")
    return {
        "schemes": schemes,
        "scheme_count": sum(1 for enabled in schemes.values() if enabled),
        "certificate_count": certificate_count,
        "certificates": certificates,
        "signature_algorithms": signature_algorithms,
        "has_debug_or_test_certificate": has_debug_or_test,
        "meta_inf_signers": inventory.get("meta_inf_signers") or [],
        "signer_lineage": lineage,
        "lineage_count": len(lineage),
        "rotation_capable": bool(schemes.get("v3") or schemes.get("v4")),
        "strict_verification": {
            "cryptographic_verification_performed": False,
            "scope": "signing metadata inspection, not signature validation",
            "status": status,
            "findings": findings,
            "recommended_next": _recommended_next(status, findings, schemes),
        },
    }


def certificate_payload(cert: Any) -> dict[str, Any]:
    raw: bytes | None = None
    dump = getattr(cert, "dump", None)
    if callable(dump):
        try:
            raw = dump()
        except Exception:
            raw = None
    subject = str(getattr(cert, "subject", "") or "").strip() or None
    issuer = str(getattr(cert, "issuer", "") or "").strip() or None
    serial = getattr(cert, "serial_number", None)
    signature_algorithm = getattr(cert, "signature_algorithm", None)
    signature_algorithm = getattr(signature_algorithm, "native", signature_algorithm)
    text_blob = " ".join(filter(None, [subject or "", issuer or ""])).lower()
    debugish = any(
        token in text_blob for token in ["android debug", "androiddebugkey", "testkey", "devkey"]
    )
    return {
        "subject": subject,
        "issuer": issuer,
        "serial_number": str(serial) if serial is not None else None,
        "signature_algorithm": str(signature_algorithm) if signature_algorithm else None,
        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
        "is_debug_or_test": debugish,
    }


def _strict_signing_findings(
    *,
    schemes: dict[str, bool],
    certificates: list[dict[str, Any]],
    meta_inf_signers: list[str],
    signature_algorithms: list[str],
    has_debug_or_test: bool,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not any(schemes.values()) and not certificates and not meta_inf_signers:
        findings.append(
            {
                "id": "no-signing-visibility",
                "severity": "fail",
                "title": "No signing material was visible",
                "message": "Neither signing schemes nor signer metadata could be confirmed from the APK.",
            }
        )
    elif schemes.get("v1") and not any(schemes.get(key) for key in ("v2", "v3", "v4")):
        findings.append(
            {
                "id": "legacy-v1-only-signing",
                "severity": "warn",
                "title": "Only legacy JAR signing is visible",
                "message": "The APK appears to rely on v1 signing only, which is weaker than modern v2/v3/v4 coverage.",
            }
        )
    if has_debug_or_test:
        findings.append(
            {
                "id": "debug-or-test-keys",
                "severity": "warn",
                "title": "Debug/test signing indicators detected",
                "message": "The signer metadata looks like debug, test, or development signing rather than production release material.",
            }
        )
    if any("sha1" in value.lower() or "md5" in value.lower() for value in signature_algorithms):
        findings.append(
            {
                "id": "weak-signature-algorithm",
                "severity": "warn",
                "title": "Weak signature algorithm indicators detected",
                "message": "One or more certificate signature algorithms use legacy SHA-1 or MD5 identifiers.",
            }
        )
    if not certificates and meta_inf_signers:
        findings.append(
            {
                "id": "meta-inf-only-signers",
                "severity": "warn",
                "title": "Only META-INF signer filenames were visible",
                "message": "Signer filenames were present, but parsed certificate details were not available from the APK library layer.",
            }
        )
    return findings


def _recommended_next(status: str, findings: list[dict[str, Any]], schemes: dict[str, bool]) -> str:
    if status == "fail":
        return "Verify the APK is intact and re-run signing inspection before trusting any certificate assumptions."
    if any(item.get("id") == "debug-or-test-keys" for item in findings):
        return (
            "Treat the APK as non-production until release signing can be confirmed independently."
        )
    if schemes.get("v3") or schemes.get("v4"):
        return (
            "Modern signing is visible; pivot to manifest/components and code-signal review next."
        )
    if any(item.get("id") == "legacy-v1-only-signing" for item in findings):
        return "Prioritize a source of truth for release provenance because only legacy signing coverage was visible."
    return (
        "Signing visibility looks reasonable; move on to manifest surface and code-signal review."
    )
