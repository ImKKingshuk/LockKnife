from __future__ import annotations



import dataclasses

import json

import pathlib

from typing import Any, Sequence



from lockknife.core.serialize import write_json



from lockknife.core._case_common import (
    _json_safe_value,
    _runtime_session_log_path,
    _runtime_session_summary_path,
    _sha256_file,
    _utc_now,
    load_case_manifest,
    save_case_manifest,
)

from lockknife.core._case_models import CaseRuntimeScript, CaseRuntimeSession, CaseManifest



def _next_runtime_session_id(manifest: CaseManifest) -> str:
    return f"rt-{len(manifest.runtime_sessions) + 1:04d}"

def _find_runtime_session_index(manifest: CaseManifest, session_id: str) -> int | None:
    for index, session in enumerate(manifest.runtime_sessions):
        if session.session_id == session_id:
            return index
    return None

def _next_runtime_script_id(session: CaseRuntimeSession) -> str:
    return f"{session.session_id}-script-{len(session.script_inventory) + 1:03d}"

def _runtime_script_payload(script: CaseRuntimeScript) -> dict[str, Any]:
    return dataclasses.asdict(script)

def _runtime_session_summary_payload(session: CaseRuntimeSession) -> dict[str, Any]:
    metadata = session.metadata if isinstance(session.metadata, dict) else {}
    preflight_obj = metadata.get("preflight")
    preflight = preflight_obj if isinstance(preflight_obj, dict) else {}
    compatibility_obj = preflight.get("compatibility")
    compatibility = compatibility_obj if isinstance(compatibility_obj, dict) else {}
    return {
        "session_id": session.session_id,
        "name": session.name,
        "app_id": session.app_id,
        "session_kind": session.session_kind,
        "attach_mode": session.attach_mode,
        "status": session.status,
        "device_id": session.device_id,
        "pid": session.pid,
        "connect_count": session.connect_count,
        "reload_count": session.reload_count,
        "event_count": session.event_count,
        "last_event_at_utc": session.last_event_at_utc,
        "active_script_id": session.active_script_id,
        "script_count": len(session.script_inventory),
        "logs_path": session.logs_path,
        "summary_path": session.summary_path,
        "latest_message": session.latest_message,
        "error_message": session.error_message,
        "recovery_hint": session.recovery_hint,
        "preflight_status": preflight.get("status"),
        "compatibility_warning_count": compatibility.get("warning_count") or 0,
        "result_artifact_ids": list(session.result_artifact_ids),
        "updated_at_utc": session.updated_at_utc,
        "started_at_utc": session.started_at_utc,
        "last_connected_at_utc": session.last_connected_at_utc,
        "ended_at_utc": session.ended_at_utc,
    }

def _runtime_session_logs_tail(
    case_dir: pathlib.Path,
    session: CaseRuntimeSession,
    *,
    limit: int = 50,
) -> list[dict[str, Any]]:
    offset = max(session.event_count - max(limit, 0), 0)
    events = _runtime_session_events(case_dir, session, offset=offset, limit=limit)
    return [entry["event"] for entry in events]

def _runtime_session_events(
    case_dir: pathlib.Path,
    session: CaseRuntimeSession,
    *,
    offset: int = 0,
    limit: int = 50,
) -> list[dict[str, Any]]:
    _ = case_dir
    if not session.logs_path:
        return []
    path = pathlib.Path(session.logs_path)
    if not path.exists():
        return []
    safe_offset = max(offset, 0)
    safe_limit = max(limit, 0)
    lines = path.read_text(encoding="utf-8").splitlines()
    selected = lines[safe_offset : safe_offset + safe_limit] if safe_limit else []
    events: list[dict[str, Any]] = []
    for index, line in enumerate(selected, start=safe_offset):
        try:
            parsed = json.loads(line)
        except Exception:
            parsed = {"timestamp_utc": _utc_now(), "event_type": "raw", "message": line}
        events.append({"cursor": index + 1, "event": parsed})
    return events

def _runtime_session_detail_payload(
    case_dir: pathlib.Path,
    session: CaseRuntimeSession,
    *,
    event_limit: int = 50,
    event_cursor: int | None = None,
) -> dict[str, Any]:
    stream_offset = max(event_cursor or 0, 0)
    stream_events = _runtime_session_events(case_dir, session, offset=stream_offset, limit=event_limit)
    payload = _runtime_session_summary_payload(session)
    payload.update(
        {
            "metadata": _json_safe_value(session.metadata),
            "script_inventory": [_runtime_script_payload(script) for script in session.script_inventory],
            "events_tail": _runtime_session_logs_tail(case_dir, session, limit=event_limit),
            "event_stream": {
                "requested_cursor": event_cursor,
                "returned_count": len(stream_events),
                "events": stream_events,
                "next_cursor": session.event_count,
                "has_more": session.event_count > (stream_offset + len(stream_events)),
            },
        }
    )
    return payload

def _write_runtime_session_summary(case_dir: pathlib.Path, session: CaseRuntimeSession) -> None:
    if not session.summary_path:
        return
    path = pathlib.Path(session.summary_path)
    write_json(path, _runtime_session_detail_payload(case_dir, session, event_limit=200))

def start_case_runtime_session(
    case_dir: pathlib.Path,
    *,
    name: str,
    app_id: str,
    session_kind: str,
    attach_mode: str,
    device_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> CaseRuntimeSession:
    manifest = load_case_manifest(case_dir)
    now = _utc_now()
    session_id = _next_runtime_session_id(manifest)
    session = CaseRuntimeSession(
        session_id=session_id,
        name=name,
        app_id=app_id,
        session_kind=session_kind,
        attach_mode=attach_mode,
        status="created",
        created_at_utc=now,
        updated_at_utc=now,
        started_at_utc=now,
        last_connected_at_utc=None,
        ended_at_utc=None,
        device_id=device_id,
        pid=None,
        connect_count=0,
        reload_count=0,
        event_count=0,
        last_event_at_utc=None,
        active_script_id=None,
        logs_path=str(_runtime_session_log_path(case_dir, session_id)),
        summary_path=str(_runtime_session_summary_path(case_dir, session_id)),
        latest_message="Runtime session created",
        error_message=None,
        recovery_hint=None,
        result_artifact_ids=[],
        script_inventory=[],
        metadata={str(key): _json_safe_value(value) for key, value in (metadata or {}).items()},
    )
    manifest.runtime_sessions.append(session)
    manifest.updated_at_utc = now
    save_case_manifest(case_dir, manifest)
    if session.logs_path is not None:
        pathlib.Path(session.logs_path).write_text("", encoding="utf-8")
    _write_runtime_session_summary(case_dir, session)
    return session

def add_case_runtime_session_script(
    case_dir: pathlib.Path,
    *,
    session_id: str,
    label: str,
    path: str,
    source_command: str,
    source_kind: str = "snapshot",
    source_path: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> CaseRuntimeSession:
    manifest = load_case_manifest(case_dir)
    index = _find_runtime_session_index(manifest, session_id)
    if index is None:
        raise ValueError(f"Runtime session {session_id} not found")
    existing = manifest.runtime_sessions[index]
    sha256, _size = _sha256_file(pathlib.Path(path))
    try:
        script_text = pathlib.Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        script_text = ""
    preview = next((line.strip() for line in script_text.splitlines() if line.strip()), "")[:120] or None
    script = CaseRuntimeScript(
        script_id=_next_runtime_script_id(existing),
        label=label,
        path=str(path),
        sha256=sha256,
        source_command=source_command,
        created_at_utc=_utc_now(),
        source_kind=source_kind,
        source_path=source_path,
        metadata={
            **{str(key): _json_safe_value(value) for key, value in (metadata or {}).items()},
            "size_bytes": _size,
            "line_count": len(script_text.splitlines()),
            "preview": preview,
        },
    )
    session = dataclasses.replace(
        existing,
        updated_at_utc=_utc_now(),
        active_script_id=script.script_id,
        script_inventory=[*existing.script_inventory, script],
        latest_message=f"Saved script {script.label}",
    )
    manifest.runtime_sessions[index] = session
    manifest.updated_at_utc = session.updated_at_utc
    save_case_manifest(case_dir, manifest)
    _write_runtime_session_summary(case_dir, session)
    return session

def update_case_runtime_session(
    case_dir: pathlib.Path,
    *,
    session_id: str,
    status: str | None = None,
    pid: int | None = None,
    attach_mode: str | None = None,
    latest_message: str | None = None,
    error_message: str | None = None,
    recovery_hint: str | None = None,
    connect_increment: int = 0,
    reload_increment: int = 0,
    result_artifact_ids_append: Sequence[str] | None = None,
    metadata_updates: dict[str, Any] | None = None,
    ended: bool = False,
    clear_error: bool = False,
) -> CaseRuntimeSession:
    manifest = load_case_manifest(case_dir)
    index = _find_runtime_session_index(manifest, session_id)
    if index is None:
        raise ValueError(f"Runtime session {session_id} not found")
    existing = manifest.runtime_sessions[index]
    now = _utc_now()
    session = dataclasses.replace(
        existing,
        status=status or existing.status,
        updated_at_utc=now,
        last_connected_at_utc=now if connect_increment > 0 else existing.last_connected_at_utc,
        ended_at_utc=now if ended else existing.ended_at_utc,
        pid=pid if pid is not None else existing.pid,
        attach_mode=attach_mode or existing.attach_mode,
        latest_message=latest_message or existing.latest_message,
        error_message=None if clear_error else (error_message if error_message is not None else existing.error_message),
        recovery_hint=recovery_hint if recovery_hint is not None else existing.recovery_hint,
        connect_count=existing.connect_count + max(connect_increment, 0),
        reload_count=existing.reload_count + max(reload_increment, 0),
        result_artifact_ids=[*existing.result_artifact_ids, *(result_artifact_ids_append or [])],
        metadata={
            **existing.metadata,
            **{str(key): _json_safe_value(value) for key, value in (metadata_updates or {}).items()},
        },
    )
    manifest.runtime_sessions[index] = session
    manifest.updated_at_utc = now
    save_case_manifest(case_dir, manifest)
    _write_runtime_session_summary(case_dir, session)
    return session

def record_case_runtime_session_event(
    case_dir: pathlib.Path,
    *,
    session_id: str,
    event: dict[str, Any],
) -> CaseRuntimeSession:
    manifest = load_case_manifest(case_dir)
    index = _find_runtime_session_index(manifest, session_id)
    if index is None:
        raise ValueError(f"Runtime session {session_id} not found")
    existing = manifest.runtime_sessions[index]
    path = pathlib.Path(existing.logs_path or _runtime_session_log_path(case_dir, session_id))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(_json_safe_value(event), default=str) + "\n")
    now = _utc_now()
    session = dataclasses.replace(
        existing,
        updated_at_utc=now,
        event_count=existing.event_count + 1,
        last_event_at_utc=event.get("timestamp_utc") if isinstance(event.get("timestamp_utc"), str) else now,
        latest_message=str(event.get("message") or event.get("event_type") or existing.latest_message or "Runtime event"),
        logs_path=str(path),
    )
    manifest.runtime_sessions[index] = session
    manifest.updated_at_utc = now
    save_case_manifest(case_dir, manifest)
    _write_runtime_session_summary(case_dir, session)
    return session

def query_case_runtime_sessions(
    case_dir: pathlib.Path,
    *,
    statuses: Sequence[str] | None = None,
    session_kinds: Sequence[str] | None = None,
    attach_modes: Sequence[str] | None = None,
    query: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    manifest = load_case_manifest(case_dir)
    status_set = {value for value in (statuses or []) if value}
    kind_set = {value for value in (session_kinds or []) if value}
    mode_set = {value for value in (attach_modes or []) if value}
    needle = (query or "").strip().lower()

    sessions = list(manifest.runtime_sessions)
    if status_set:
        sessions = [session for session in sessions if session.status in status_set]
    if kind_set:
        sessions = [session for session in sessions if session.session_kind in kind_set]
    if mode_set:
        sessions = [session for session in sessions if session.attach_mode in mode_set]
    if needle:
        sessions = [
            session
            for session in sessions
            if needle in session.session_id.lower()
            or needle in session.name.lower()
            or needle in session.app_id.lower()
            or needle in session.session_kind.lower()
            or needle in (session.latest_message or "").lower()
            or needle in (session.error_message or "").lower()
        ]
    sessions.sort(key=lambda item: item.updated_at_utc, reverse=True)
    if limit is not None and limit > 0:
        sessions = sessions[:limit]

    return {
        "case_dir": str(case_dir),
        "case_id": manifest.case_id,
        "title": manifest.title,
        "session_count": len(sessions),
        "total_session_count": len(manifest.runtime_sessions),
        "filters": {
            "statuses": list(statuses or []),
            "session_kinds": list(session_kinds or []),
            "attach_modes": list(attach_modes or []),
            "query": query or "",
            "limit": limit,
        },
        "sessions": [_runtime_session_summary_payload(session) for session in sessions],
    }

def case_runtime_session_details(
    case_dir: pathlib.Path,
    *,
    session_id: str,
    event_limit: int = 50,
    event_cursor: int | None = None,
) -> dict[str, Any] | None:
    manifest = load_case_manifest(case_dir)
    index = _find_runtime_session_index(manifest, session_id)
    if index is None:
        return None
    session = manifest.runtime_sessions[index]
    return {
        "case_dir": str(case_dir),
        "case_id": manifest.case_id,
        "session": _runtime_session_detail_payload(case_dir, session, event_limit=event_limit, event_cursor=event_cursor),
    }
