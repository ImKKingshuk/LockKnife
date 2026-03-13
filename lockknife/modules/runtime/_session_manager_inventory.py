from __future__ import annotations

from typing import Any

from lockknife.modules.runtime.hooks import list_builtin_runtime_scripts, suggest_builtin_runtime_scripts
from lockknife.modules.runtime._session_manager_events import (
    build_runtime_event_summary,
    build_runtime_failure_context,
)


def enrich_runtime_session_payload(payload: dict[str, Any], *, live: bool) -> dict[str, Any]:
    session = payload.get("session")
    if not isinstance(session, dict):
        return payload
    preflight = _preflight_from_session(session, payload)
    script_summary = build_script_inventory_summary(
        session.get("script_inventory") or [],
        session.get("active_script_id"),
    )
    event_summary = build_runtime_event_summary(session.get("events_tail") or [])
    failure_context = build_runtime_failure_context(session, preflight)
    compatibility = preflight.get("compatibility") if isinstance(preflight, dict) else None
    compatibility_status = compatibility.get("status") if isinstance(compatibility, dict) else None
    compatibility_warning_count = compatibility.get("warning_count") if isinstance(compatibility, dict) else 0
    compatibility_fail_count = compatibility.get("fail_count") if isinstance(compatibility, dict) else 0
    preflight_status = preflight.get("status") if isinstance(preflight, dict) else None
    dashboard = {
        "mode": "session-detail",
        "session_id": session.get("session_id"),
        "status": session.get("status"),
        "live": live,
        "session_kind": session.get("session_kind"),
        "attach_mode": session.get("attach_mode"),
        "app_id": session.get("app_id"),
        "connect_count": session.get("connect_count") or 0,
        "reload_count": session.get("reload_count") or 0,
        "event_count": session.get("event_count") or 0,
        "script_count": script_summary["count"],
        "preflight_status": preflight_status,
        "compatibility_status": compatibility_status,
        "compatibility_warning_count": compatibility_warning_count,
        "compatibility_fail_count": compatibility_fail_count,
        "recommended_next_action": _session_recommended_next(session, live, preflight, failure_context),
        "latest_event": event_summary.get("latest"),
        "active_script_label": script_summary.get("active_label"),
    }
    session["preflight"] = preflight
    session["script_inventory_summary"] = script_summary
    session["event_summary"] = event_summary
    payload["available_builtin_scripts"] = list_builtin_runtime_scripts()
    payload["suggested_builtin_scripts"] = suggest_builtin_runtime_scripts(
        str(session.get("app_id") or ""),
        session_kind=str(session.get("session_kind") or "") or None,
    )
    session["compatibility"] = compatibility or {
        "status": "pass",
        "finding_count": 0,
        "warning_count": 0,
        "fail_count": 0,
        "findings": [],
        "recommended_next_action": None,
    }
    if failure_context is not None:
        session["failure_context"] = failure_context
    payload["live"] = live
    payload["runtime_dashboard"] = dashboard
    return payload


def enrich_runtime_inventory_payload(payload: dict[str, Any]) -> dict[str, Any]:
    sessions = payload.get("sessions") or []
    if not isinstance(sessions, list):
        return payload
    live_ids = {
        str(item)
        for item in payload.get("live_session_ids") or []
        if str(item).strip()
    }
    active_count = 0
    failed_count = 0
    compatibility_warning_count = 0
    script_count = 0
    previews = []
    for session in sessions:
        if not isinstance(session, dict):
            continue
        live = str(session.get("session_id") or "") in live_ids
        session["live"] = live
        if session.get("status") == "active":
            active_count += 1
        if session.get("status") == "failed":
            failed_count += 1
        compatibility_warning_count += int(session.get("compatibility_warning_count") or 0)
        script_count += int(session.get("script_count") or 0)
        previews.append(
            {
                "session_id": session.get("session_id"),
                "status": session.get("status"),
                "live": live,
                "session_kind": session.get("session_kind"),
                "latest_message": session.get("latest_message"),
                "preflight_status": session.get("preflight_status"),
                "compatibility_warning_count": session.get("compatibility_warning_count") or 0,
                "script_count": session.get("script_count") or 0,
                "updated_at_utc": session.get("updated_at_utc"),
            }
        )
    payload["runtime_dashboard"] = {
        "mode": "inventory",
        "session_count": payload.get("session_count") or 0,
        "total_session_count": payload.get("total_session_count") or 0,
        "live_session_count": len(live_ids),
        "active_session_count": active_count,
        "failed_session_count": failed_count,
        "compatibility_warning_count": compatibility_warning_count,
        "script_count": script_count,
        "builtin_script_count": len(list_builtin_runtime_scripts()),
        "recommended_next_action": _inventory_recommended_next(previews, live_ids),
        "session_previews": previews[:5],
    }
    payload["available_builtin_scripts"] = list_builtin_runtime_scripts()
    return payload


def build_script_inventory_summary(
    scripts: list[dict[str, Any]],
    active_script_id: Any,
) -> dict[str, Any]:
    items = []
    active_label = None
    latest_label = None
    for raw in scripts:
        if not isinstance(raw, dict):
            continue
        metadata_obj = raw.get("metadata")
        metadata = metadata_obj if isinstance(metadata_obj, dict) else {}
        item = {
            "script_id": raw.get("script_id"),
            "label": raw.get("label"),
            "source_kind": raw.get("source_kind"),
            "source_command": raw.get("source_command"),
            "created_at_utc": raw.get("created_at_utc"),
            "path": raw.get("path"),
            "size_bytes": metadata.get("size_bytes"),
            "line_count": metadata.get("line_count"),
            "preview": metadata.get("preview"),
            "builtin_script": metadata.get("builtin_script"),
            "builtin_title": metadata.get("builtin_title"),
            "active": raw.get("script_id") == active_script_id,
        }
        items.append(item)
        latest_label = str(raw.get("label") or latest_label or "") or latest_label
        if item["active"]:
            active_label = str(raw.get("label") or active_label or "") or active_label
    return {
        "count": len(items),
        "active_script_id": active_script_id,
        "active_label": active_label,
        "latest_label": latest_label,
        "items": items[-5:],
    }


def _preflight_from_session(session: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any] | None:
    payload_preflight = payload.get("preflight")
    if isinstance(payload_preflight, dict):
        return payload_preflight
    metadata = session.get("metadata")
    if isinstance(metadata, dict):
        metadata_preflight = metadata.get("preflight")
        if isinstance(metadata_preflight, dict):
            return metadata_preflight
    return None


def _session_recommended_next(
    session: dict[str, Any],
    live: bool,
    preflight: dict[str, Any] | None,
    failure_context: dict[str, Any] | None,
) -> str:
    if failure_context is not None:
        recovery_hint = failure_context.get("recovery_hint") if isinstance(failure_context, dict) else None
        return str(recovery_hint or "Review the failed checks and reconnect only after the target is ready.")
    if live:
        return "Inspect recent runtime events and keep reload/reconnect controls ready while the session stays live."
    if isinstance(preflight, dict) and preflight.get("readiness", {}).get("recommended_action"):
        return str(preflight["readiness"]["recommended_action"])
    return "Open the runtime session detail to inspect saved scripts, recent events, and compatibility notes."


def _inventory_recommended_next(
    previews: list[dict[str, Any]],
    live_ids: set[str],
) -> str:
    if live_ids:
        return "Open Session detail on a live session first so you can inspect recent events and hot-reload readiness."
    if any(item.get("status") == "failed" for item in previews):
        return "Review the failed session detail first, then use reconnect once the target-readiness blockers are cleared."
    if previews:
        return "Open the newest runtime session to inspect saved scripts and compatibility posture before reconnecting."
    return "Run Runtime preflight first, then launch a managed hook, SSL bypass, or trace session."
