from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import shutil
import subprocess  # nosec B404
import time
from typing import Any


@dataclasses.dataclass(frozen=True)
class EvidenceItem:
    name: str
    path: str
    sha256: str | None = None
    category: str | None = None
    source_command: str | None = None
    device_serial: str | None = None
    collected_at_utc: str | None = None
    size_bytes: int | None = None
    integrity_status: str | None = None
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)


def build_chain_of_custody_payload(
    *,
    case_id: str,
    examiner: str,
    notes: str | None,
    evidence: list[EvidenceItem],
) -> dict[str, Any]:
    generated_at = time.strftime("%Y-%m-%d %H:%M:%S %z")
    previous_hash = "0" * 64
    entries: list[dict[str, Any]] = []
    for index, item in enumerate(evidence, start=1):
        resolved = _resolved_evidence(item)
        payload = {
            "index": index,
            "case_id": case_id,
            "examiner": examiner,
            "name": resolved.name,
            "path": resolved.path,
            "sha256": resolved.sha256,
            "category": resolved.category,
            "source_command": resolved.source_command,
            "device_serial": resolved.device_serial,
            "collected_at_utc": resolved.collected_at_utc,
            "size_bytes": resolved.size_bytes,
            "integrity_status": resolved.integrity_status,
            "metadata": resolved.metadata,
            "previous_hash": previous_hash,
        }
        entry_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        entries.append({**payload, "entry_hash": entry_hash})
        previous_hash = entry_hash
    verification = verify_chain_of_custody(entries)
    return {
        "case_id": case_id,
        "examiner": examiner,
        "generated_at": generated_at,
        "notes": notes,
        "entry_count": len(entries),
        "chain_head_sha256": previous_hash if entries else None,
        "entries": entries,
        "verification": verification,
    }


def _sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_chain_of_custody(
    *,
    case_id: str,
    examiner: str,
    notes: str | None,
    evidence: list[EvidenceItem],
) -> str:
    payload = build_chain_of_custody_payload(
        case_id=case_id, examiner=examiner, notes=notes, evidence=evidence
    )
    lines: list[str] = []
    lines.append("Chain of Custody")
    lines.append("")
    lines.append(f"Case ID: {case_id}")
    lines.append(f"Examiner: {examiner}")
    lines.append(f"Generated: {payload['generated_at']}")
    if payload.get("chain_head_sha256"):
        lines.append(f"Chain head SHA256: {payload['chain_head_sha256']}")
    verification = payload.get("verification") or {}
    if isinstance(verification, dict):
        lines.append(f"Chain verification: {verification.get('status', 'unknown')}")
    lines.append("")
    if notes:
        lines.append("Notes:")
        lines.append(notes)
        lines.append("")
    lines.append("Evidence:")
    for entry in payload["entries"]:
        lines.append(f"- {entry['name']}")
        lines.append(f"  Path: {entry['path']}")
        if entry.get("category"):
            lines.append(f"  Category: {entry['category']}")
        if entry.get("source_command"):
            lines.append(f"  Source command: {entry['source_command']}")
        if entry.get("device_serial"):
            lines.append(f"  Device serial: {entry['device_serial']}")
        if entry.get("collected_at_utc"):
            lines.append(f"  Collected: {entry['collected_at_utc']}")
        if entry.get("size_bytes") is not None:
            lines.append(f"  Size: {entry['size_bytes']} bytes")
        if entry.get("sha256"):
            lines.append(f"  SHA256: {entry['sha256']}")
        if entry.get("integrity_status"):
            lines.append(f"  Integrity status: {entry['integrity_status']}")
        lines.append(f"  Previous hash: {entry['previous_hash']}")
        lines.append(f"  Entry hash: {entry['entry_hash']}")
    lines.append("")
    return "\n".join(lines)


def write_chain_of_custody(text: str, output_path: pathlib.Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")


def verify_chain_of_custody(entries: list[dict[str, Any]]) -> dict[str, Any]:
    previous_hash = "0" * 64
    for index, entry in enumerate(entries, start=1):
        if str(entry.get("previous_hash") or "") != previous_hash:
            return {"status": "invalid", "entry_index": index, "reason": "previous-hash-mismatch"}
        payload = {key: value for key, value in entry.items() if key != "entry_hash"}
        recalculated = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if str(entry.get("entry_hash") or "") != recalculated:
            return {"status": "invalid", "entry_index": index, "reason": "entry-hash-mismatch"}
        previous_hash = recalculated
    return {
        "status": "verified",
        "entry_count": len(entries),
        "chain_head_sha256": previous_hash if entries else None,
    }


def sign_report_file(
    output_path: pathlib.Path, *, key_id: str | None = None, armor: bool = True
) -> dict[str, Any]:
    executable = shutil.which("gpg") or shutil.which("gpg2")
    if executable is None:
        return {"status": "unavailable", "reason": "gpg-not-found"}
    signature_path = output_path.with_suffix(output_path.suffix + (".asc" if armor else ".sig"))
    command = [executable, "--batch", "--yes", "--detach-sign"]
    if armor:
        command.append("--armor")
    if key_id:
        command.extend(["--local-user", key_id])
    command.extend(["--output", str(signature_path), str(output_path)])
    result = subprocess.run(command, capture_output=True, text=True)  # nosec B603
    if result.returncode != 0:
        return {
            "status": "error",
            "reason": "gpg-sign-failed",
            "stderr": (result.stderr or "").strip()[:400],
            "command": command,
        }
    return {
        "status": "signed",
        "signature_path": str(signature_path),
        "command": command,
        "armor": armor,
        "key_id": key_id,
    }


def _resolved_evidence(item: EvidenceItem) -> EvidenceItem:
    sha256 = item.sha256
    path = pathlib.Path(item.path)
    size_bytes = item.size_bytes
    if path.exists() and path.is_file():
        if sha256 is None:
            try:
                sha256 = _sha256_file(path)
            except OSError:
                sha256 = None
        if size_bytes is None:
            try:
                size_bytes = path.stat().st_size
            except OSError:
                size_bytes = None
    return dataclasses.replace(item, sha256=sha256, size_bytes=size_bytes)
