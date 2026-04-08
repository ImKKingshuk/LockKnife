from __future__ import annotations

import shlex
from typing import Any

from lockknife.core.device import DeviceManager


def unique_providers(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for item in items:
        authority = _provider_authority(item)
        if not authority or authority in seen:
            continue
        seen.add(authority)
        unique.append(item)
    return unique


def provider_review_notes(item: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    if not item.get("read_permission") and not item.get("write_permission"):
        notes.append("No explicit read/write permission guards")
    if item.get("grant_uri_permissions"):
        notes.append("grantUriPermissions enabled")
    if item.get("authorities"):
        notes.append(
            f"Authorities: {', '.join(str(value) for value in item.get('authorities') or [])}"
        )
    return notes


def probe_provider(
    devices: DeviceManager, serial: str, package: str, item: dict[str, Any]
) -> dict[str, Any]:
    authority = _provider_authority(item) or package
    command = f"cmd package resolve-content-provider {shlex.quote(authority)}"
    result = _probe_command(
        devices, serial, command, key="authority", value=authority, match_terms=[package, authority]
    )
    result.update(
        {
            "component": item.get("name"),
            "grant_uri_permissions": bool(item.get("grant_uri_permissions")),
            "review_notes": provider_review_notes(item),
        }
    )
    return result


def _provider_authority(item: dict[str, Any]) -> str | None:
    for value in item.get("authorities") or []:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _probe_command(
    devices: DeviceManager,
    serial: str,
    command: str,
    *,
    key: str,
    value: str,
    match_terms: list[str],
) -> dict[str, Any]:
    try:
        output = devices.shell(serial, command, timeout_s=10.0)
    except Exception as exc:  # pragma: no cover - exercised through callers
        return {key: value, "command": command, "status": "error", "details": str(exc)}
    lowered = output.lower()
    resolved = bool(output.strip()) and not any(
        token in lowered for token in ("no provider", "unable to", "not found")
    )
    if match_terms:
        resolved = resolved and any(term.lower() in lowered for term in match_terms if term)
    return {
        key: value,
        "command": command,
        "status": "resolved" if resolved else "not-resolved",
        "details": output.strip()[:400],
    }
