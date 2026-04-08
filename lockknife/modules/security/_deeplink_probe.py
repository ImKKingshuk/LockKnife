from __future__ import annotations

import shlex
from typing import Any

from lockknife.core.device import DeviceManager


def deeplink_uri(item: dict[str, Any]) -> str:
    if isinstance(item.get("uri"), str) and item["uri"].strip():
        return str(item["uri"]).strip()
    data_obj = item.get("data")
    data = data_obj if isinstance(data_obj, dict) else {}
    scheme = str(item.get("scheme") or data.get("scheme") or "https")
    host = str(item.get("host") or data.get("host") or "example.invalid")
    path = str(
        item.get("path")
        or data.get("path")
        or data.get("pathPrefix")
        or data.get("pathPattern")
        or "/"
    )
    if host and not path.startswith("/"):
        path = f"/{path}"
    if host:
        return f"{scheme}://{host}{path}"
    return f"{scheme}://"


def unique_deeplinks(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for item in items:
        uri = deeplink_uri(item)
        if uri in seen:
            continue
        seen.add(uri)
        unique.append(item)
    return unique


def deeplink_review_notes(item: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    if item.get("browsable"):
        notes.append("Browsable entry point")
    if item.get("auto_verify"):
        notes.append("App Links autoVerify enabled")
    uri = deeplink_uri(item)
    if uri.startswith("http://"):
        notes.append("HTTP scheme review recommended")
    elif "://" in uri and not uri.startswith(("https://", "http://")):
        notes.append("Custom scheme collision review recommended")
    return notes


def probe_deeplink(
    devices: DeviceManager, serial: str, package: str, item: dict[str, Any]
) -> dict[str, Any]:
    uri = deeplink_uri(item)
    command = (
        f"cmd package query-intent-activities -a android.intent.action.VIEW -d {shlex.quote(uri)}"
    )
    result = _probe_command(devices, serial, command, key="uri", value=uri, match_terms=[package])
    result.update(
        {
            "component": item.get("component"),
            "browsable": bool(item.get("browsable")),
            "auto_verify": bool(item.get("auto_verify")),
            "review_notes": deeplink_review_notes(item),
        }
    )
    return result


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
        token in lowered for token in ("no activities", "unable to", "not found")
    )
    if match_terms:
        resolved = resolved and any(term.lower() in lowered for term in match_terms if term)
    return {
        key: value,
        "command": command,
        "status": "resolved" if resolved else "not-resolved",
        "details": output.strip()[:400],
    }
