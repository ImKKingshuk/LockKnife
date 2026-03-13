from __future__ import annotations



import pathlib

import re

import threading

from dataclasses import dataclass

from typing import Any



from lockknife.core._case_common import _utc_now
from lockknife.core.case import case_output_path, case_runtime_session_details, record_case_runtime_session_event, register_case_artifact

from lockknife.modules.runtime.frida_manager import FridaManager
from lockknife.modules.runtime.hooks import get_builtin_runtime_script



def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "runtime"

def _runtime_now() -> str:
    return _utc_now()

def _artifact_id(value: Any) -> str | None:
    return getattr(value, "artifact_id", None)

def _recovery_hint(exc: Exception) -> str:
    text = str(exc).lower()
    if "module 'frida'" in text or "pip install 'lockknife[frida]'" in text:
        return "Install the optional Frida extras and retry runtime instrumentation."
    if "permission" in text or "access denied" in text:
        return "Verify adb/root permissions and the Frida server privileges on the device."
    if "process not found" in text or "unable to find process" in text:
        return "Use spawn mode or launch the target app before attaching."
    if "protocol" in text or "incompatible" in text or "version" in text:
        return "Check the Frida client/server versions and ABI compatibility on the host and device."
    return "Re-run runtime preflight, confirm the app/process state, and retry the session action."

@dataclass
class LiveRuntimeSession:
    session_id: str
    case_dir: pathlib.Path
    manager: FridaManager
    handle: Any
    session: Any
    script: Any

def _register_runtime_artifact(
    *,
    case_dir: pathlib.Path,
    path: pathlib.Path,
    category: str,
    source_command: str,
    device_id: str | None,
    input_paths: list[str] | None = None,
    parent_artifact_ids: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> str | None:
    artifact = register_case_artifact(
        case_dir=case_dir,
        path=path,
        category=category,
        source_command=source_command,
        device_serial=device_id,
        input_paths=input_paths,
        parent_artifact_ids=parent_artifact_ids,
        metadata=metadata,
    )
    return _artifact_id(artifact)

def _read_session_payload(case_dir: pathlib.Path, session_id: str) -> dict[str, Any]:
    payload = case_runtime_session_details(case_dir, session_id=session_id, event_limit=100)
    if payload is None:
        raise ValueError(f"Runtime session {session_id} not found")
    session = payload.get("session")
    if not isinstance(session, dict):
        raise ValueError(f"Runtime session {session_id} payload missing session details")
    return session

def _snapshot_script(
    *,
    case_dir: pathlib.Path,
    session_id: str,
    label: str,
    source: str,
) -> pathlib.Path:
    filename = f"runtime_{session_id}_{_safe_name(label)}.js"
    path = case_output_path(case_dir, area="derived", filename=filename)
    path.write_text(source, encoding="utf-8")
    return path

def _write_event(
    case_dir: pathlib.Path,
    *,
    session_id: str,
    event_type: str,
    message: str,
    level: str = "info",
    payload: dict[str, Any] | None = None,
) -> None:
    event = {
        "timestamp_utc": _runtime_now(),
        "event_type": event_type,
        "level": level,
        "message": message,
        "payload": payload or {},
    }
    record_case_runtime_session_event(case_dir, session_id=session_id, event=event)

def _close_live_session(live: LiveRuntimeSession | None) -> None:
    if live is None:
        return
    try:
        unload = getattr(live.script, "unload", None)
        if callable(unload):
            unload()
    finally:
        detach = getattr(live.session, "detach", None)
        if callable(detach):
            detach()

def _resolve_script_source(
    session_payload: dict[str, Any],
    *,
    script_path: pathlib.Path | None,
    script_source: str | None,
    builtin_script: str | None = None,
) -> tuple[str, str, pathlib.Path | None, str, dict[str, Any]]:
    if script_source is not None:
        return script_source, "inline-script", None, "inline", {}
    if builtin_script is not None:
        descriptor = get_builtin_runtime_script(builtin_script)
        source_path = pathlib.Path(str(descriptor["path"]))
        return (
            str(descriptor["source"]),
            str(descriptor["file_name"]),
            source_path,
            "builtin",
            {
                "builtin_script": descriptor["name"],
                "builtin_category": descriptor["category"],
                "builtin_title": descriptor["title"],
                "builtin_tags": descriptor["tags"],
            },
        )
    if script_path is not None:
        return script_path.read_text(encoding="utf-8"), script_path.name, script_path, "file", {}
    inventory = session_payload.get("script_inventory") or []
    if not inventory:
        raise ValueError("Runtime session does not have a saved script to reconnect or reload")
    latest = inventory[-1]
    latest_path = pathlib.Path(str(latest["path"]))
    return latest_path.read_text(encoding="utf-8"), str(latest.get("label") or latest_path.name), latest_path, "snapshot", {}



_LIVE_SESSIONS: dict[str, LiveRuntimeSession] = {}

_LIVE_SESSIONS_LOCK = threading.RLock()
