from __future__ import annotations

import shlex
from typing import Any

from lockknife.core.device import DeviceManager
from lockknife.modules.security._deeplink_probe import probe_deeplink, unique_deeplinks
from lockknife.modules.security._provider_probe import probe_provider, unique_providers

PROBE_LIMIT = 8


def probe_surface(
    devices: DeviceManager | None,
    *,
    serial: str | None,
    package: str | None,
    deeplinks: list[dict[str, Any]],
    providers: list[dict[str, Any]],
    exported_components: list[dict[str, Any]],
) -> dict[str, Any]:
    if not serial or not package:
        return {
            "attempted": False,
            "serial": serial,
            "package": package,
            "package_present": None,
            "summary": {
                "deeplink_probe_total": 0,
                "deeplink_resolved_total": 0,
                "provider_probe_total": 0,
                "provider_resolved_total": 0,
                "component_probe_total": 0,
                "component_resolved_total": 0,
                "component_interaction_total": 0,
                "component_permission_enforced_total": 0,
                "component_permission_gap_total": 0,
            },
            "deeplinks": [],
            "providers": [],
            "components": [],
            "review_queue": [],
        }
    if devices is None:
        raise ValueError("Live device probes require a device manager")

    package_command = f"pm path {shlex.quote(package)}"
    package_out = devices.shell(serial, package_command, timeout_s=10.0)
    package_present = "package:" in package_out
    deeplink_results = [
        probe_deeplink(devices, serial, package, item)
        for item in unique_deeplinks(deeplinks)[:PROBE_LIMIT]
    ]
    provider_results = [
        probe_provider(devices, serial, package, item)
        for item in unique_providers(providers)[:PROBE_LIMIT]
    ]
    component_results = [
        _probe_component(devices, serial, package, item)
        for item in _component_probe_targets(exported_components)[:PROBE_LIMIT]
    ]
    resolved_static_gaps = sum(
        1
        for item in component_results
        if item.get("static_permission_gap") and item.get("status") == "resolved"
    )
    static_gap_total = sum(
        1
        for item in _component_probe_targets(exported_components)[:PROBE_LIMIT]
        if item.get("static_permission_gap")
    )
    return {
        "attempted": True,
        "serial": serial,
        "package": package,
        "package_present": package_present,
        "package_path": package_out.strip() or None,
        "summary": {
            "deeplink_probe_total": len(deeplink_results),
            "deeplink_resolved_total": sum(
                1 for item in deeplink_results if item["status"] == "resolved"
            ),
            "provider_probe_total": len(provider_results),
            "provider_resolved_total": sum(
                1 for item in provider_results if item["status"] == "resolved"
            ),
            "component_probe_total": len(component_results),
            "component_resolved_total": sum(
                1 for item in component_results if item["status"] == "resolved"
            ),
            "component_interaction_total": sum(
                1 for item in component_results if item.get("interaction_status") == "resolved"
            ),
            "component_permission_enforced_total": sum(
                1 for item in component_results if item.get("permission_verification") == "declared"
            ),
            "component_permission_gap_total": max(
                sum(
                    1 for item in component_results if item.get("permission_verification") == "gap"
                ),
                resolved_static_gaps,
                static_gap_total,
            ),
        },
        "deeplinks": deeplink_results,
        "providers": provider_results,
        "components": component_results,
        "review_queue": _review_queue(deeplink_results, provider_results, component_results),
    }


def probe_findings(probe_results: dict[str, Any]) -> list[dict[str, Any]]:
    if not probe_results.get("attempted"):
        return []
    summary = probe_results.get("summary") or {}
    findings: list[dict[str, Any]] = []
    if summary.get("deeplink_resolved_total", 0):
        findings.append(
            {
                "id": "live_deeplink_resolution",
                "title": "Browsable deep links resolve on-device",
                "severity": "medium",
                "description": "Safe package-manager probes resolved one or more browsable deep-link entry points on the device.",
                "evidence": [
                    item.get("uri")
                    for item in probe_results.get("deeplinks", [])
                    if item.get("status") == "resolved"
                ],
            }
        )
    if summary.get("provider_resolved_total", 0):
        findings.append(
            {
                "id": "live_provider_resolution",
                "title": "Exported providers resolve on-device",
                "severity": "high",
                "description": "Safe provider-resolution probes confirmed one or more exported content-provider authorities on the device.",
                "evidence": [
                    item.get("authority")
                    for item in probe_results.get("providers", [])
                    if item.get("status") == "resolved"
                ],
            }
        )
    if summary.get("component_resolved_total", 0):
        findings.append(
            {
                "id": "live_component_resolution",
                "title": "Exported components resolve on-device",
                "severity": "medium",
                "description": "Safe package-manager probes resolved one or more exported activity, service, or receiver entry points on the device.",
                "evidence": [
                    item.get("component")
                    for item in probe_results.get("components", [])
                    if item.get("status") == "resolved"
                ],
            }
        )
    if summary.get("component_permission_gap_total", 0):
        findings.append(
            {
                "id": "live_component_permission_gap",
                "title": "Resolved components appear reachable without permission enforcement",
                "severity": "high",
                "description": "Live resolution plus missing permission guards indicates a reachable exported component surface that likely lacks caller gating.",
                "evidence": [
                    item.get("component")
                    for item in probe_results.get("components", [])
                    if item.get("permission_verification") == "gap"
                ],
            }
        )
    return findings


def _component_probe_targets(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    targets: list[dict[str, Any]] = []
    for item in items:
        component_type = str(item.get("type") or "")
        if component_type == "provider":
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        key = (component_type, name)
        if key in seen:
            continue
        seen.add(key)
        targets.append(item)
    return targets


def _probe_component(
    devices: DeviceManager, serial: str, package: str, item: dict[str, Any]
) -> dict[str, Any]:
    component = str(item.get("name") or "").strip()
    component_type = str(item.get("type") or "activity")
    if component_type == "activity":
        command = f"cmd package resolve-activity --brief -n {shlex.quote(component)}"
    elif component_type == "service":
        command = f"cmd package resolve-service --brief -n {shlex.quote(component)}"
    else:
        command = f"cmd package query-intent-receivers --brief -n {shlex.quote(component)}"
    interaction_command = _interaction_command(item)
    try:
        output = devices.shell(serial, command, timeout_s=10.0)
        interaction_output = (
            devices.shell(serial, interaction_command, timeout_s=10.0)
            if interaction_command
            else ""
        )
    except Exception as exc:  # pragma: no cover - exercised through callback/CLI plumbing
        return {
            "component": component,
            "type": component_type,
            "command": command,
            "interaction_command": interaction_command,
            "status": "error",
            "details": str(exc),
        }
    lowered = output.lower()
    interaction_lowered = interaction_output.lower()
    resolved = bool(output.strip()) and not any(
        token in lowered
        for token in ("no activities", "no services", "no receivers", "unable to", "not found")
    )
    resolved = resolved and package.lower() in lowered
    interaction_resolved = bool(interaction_output.strip()) and not any(
        token in interaction_lowered
        for token in ("no activities", "no services", "no receivers", "unable to", "not found")
    )
    interaction_resolved = (
        interaction_resolved and package.lower() in interaction_lowered
        if interaction_command
        else False
    )
    permission_verification = (
        "declared" if item.get("permission") or item.get("permission_protected") else "none"
    )
    if (resolved or interaction_resolved) and permission_verification == "none":
        permission_verification = "gap"
    return {
        "component": component,
        "type": component_type,
        "command": command,
        "interaction_command": interaction_command,
        "status": "resolved" if resolved else "not-resolved",
        "interaction_status": "resolved" if interaction_resolved else "not-resolved",
        "details": output.strip()[:400],
        "interaction_details": interaction_output.strip()[:400] if interaction_command else None,
        "permission": item.get("permission"),
        "permission_verification": permission_verification,
        "static_permission_gap": bool(item.get("static_permission_gap")),
        "review_notes": list(item.get("review_notes") or []),
    }


def _interaction_command(item: dict[str, Any]) -> str | None:
    component_type = str(item.get("type") or "activity")
    actions = [str(value) for value in item.get("actions") or [] if str(value).strip()]
    action = actions[0] if actions else None
    uri = str(item.get("probe_uri") or "").strip() or None
    if component_type == "activity" and action:
        cmd = f"cmd package query-intent-activities --brief -a {shlex.quote(action)}"
        if uri:
            cmd += f" -d {shlex.quote(uri)}"
        return cmd
    if component_type == "service" and action:
        return f"cmd package query-intent-services --brief -a {shlex.quote(action)}"
    if component_type == "receiver" and action:
        return f"cmd package query-intent-receivers --brief -a {shlex.quote(action)}"
    return None


def _review_queue(
    deeplinks: list[dict[str, Any]],
    providers: list[dict[str, Any]],
    components: list[dict[str, Any]],
) -> list[str]:
    queue: list[str] = []
    for item in providers:
        if item.get("status") == "resolved":
            queue.append(
                f"Confirmed provider authority {item.get('authority')} resolves on-device; attempt safe read-path validation next."
            )
    for item in deeplinks:
        if item.get("status") == "resolved":
            queue.append(
                f"Confirmed deep link {item.get('uri')} resolves on-device; inspect auth, session, and redirect handling."
            )
    for item in components:
        if item.get("status") == "resolved":
            queue.append(
                f"Confirmed exported {item.get('type')} {item.get('component')} resolves on-device; review caller trust assumptions."
            )
        if item.get("permission_verification") == "gap":
            queue.append(
                f"Component {item.get('component')} resolved without an explicit permission guard; validate caller restrictions next."
            )
    return queue[:6]
