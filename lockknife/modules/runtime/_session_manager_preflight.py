from __future__ import annotations

from collections.abc import Callable
from typing import Any

from lockknife.modules.runtime._compat_registry_match import evaluate_runtime_compatibility
from lockknife.modules.runtime._session_manager_shared import _recovery_hint
from lockknife.modules.runtime.frida_manager import FridaManager
from lockknife.modules.runtime.hooks import (
    list_builtin_runtime_scripts,
    suggest_builtin_runtime_scripts,
)


def runtime_preflight(
    *,
    app_id: str,
    device_id: str | None = None,
    attach_mode: str = "spawn",
    session_kind: str | None = None,
    manager_factory: Callable[[str | None], FridaManager] | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    manager: FridaManager | None = None
    try:
        manager_factory = manager_factory or FridaManager
        manager = manager_factory(device_id)
        checks.append(
            {
                "check": "frida-client",
                "status": "pass",
                "message": "Frida client bindings loaded successfully.",
            }
        )
    except Exception as exc:
        message = str(exc)
        checks.append({"check": "frida-client", "status": "fail", "message": message})
        return {
            "app_id": app_id,
            "device_id": device_id,
            "attach_mode": attach_mode,
            "session_kind": session_kind,
            "status": "fail",
            "checks": checks,
            "compatibility": {
                "status": "fail",
                "finding_count": 0,
                "warning_count": 0,
                "fail_count": 0,
                "findings": [],
                "recommended_next_action": _recovery_hint(exc),
            },
            "target": {
                "device": None,
                "application_available": None,
                "running_pid": None,
            },
            "readiness": {
                "status": "blocked",
                "ready": False,
                "blocked_checks": ["frida-client"],
                "warned_checks": [],
                "recommended_action": _recovery_hint(exc),
                "next_actions": [
                    {
                        "action": "install-runtime-extras",
                        "status": "blocked",
                        "message": _recovery_hint(exc),
                    }
                ],
            },
            "recovery_hint": _recovery_hint(exc),
        }

    device: dict[str, Any] | None = None
    try:
        device = (
            manager.describe_device() if hasattr(manager, "describe_device") else {"id": device_id}
        )
        checks.append(
            {
                "check": "device",
                "status": "pass",
                "message": f"Frida device ready: {device.get('id') or device_id or 'usb'}.",
                "device": device,
            }
        )
    except Exception as exc:
        checks.append({"check": "device", "status": "fail", "message": str(exc)})
        return {
            "app_id": app_id,
            "device_id": device_id,
            "attach_mode": attach_mode,
            "session_kind": session_kind,
            "status": "fail",
            "checks": checks,
            "compatibility": {
                "status": "fail",
                "finding_count": 0,
                "warning_count": 0,
                "fail_count": 0,
                "findings": [],
                "recommended_next_action": _recovery_hint(exc),
            },
            "target": {
                "device": None,
                "application_available": None,
                "running_pid": None,
            },
            "readiness": {
                "status": "blocked",
                "ready": False,
                "blocked_checks": [check["check"] for check in checks if check["status"] == "fail"],
                "warned_checks": [],
                "recommended_action": _recovery_hint(exc),
                "next_actions": [
                    {
                        "action": "fix-device-readiness",
                        "status": "blocked",
                        "message": _recovery_hint(exc),
                    }
                ],
            },
            "recovery_hint": _recovery_hint(exc),
        }

    available: bool | None = None
    try:
        available = (
            manager.application_available(app_id)
            if hasattr(manager, "application_available")
            else False
        )
        checks.append(
            {
                "check": "application",
                "status": "pass" if available else "warn",
                "message": (
                    f"Application {app_id} is visible on the target."
                    if available
                    else f"Application visibility for {app_id} could not be confirmed before launch."
                ),
            }
        )
    except Exception as exc:
        checks.append({"check": "application", "status": "warn", "message": str(exc)})
        available = False

    running_pid: int | None = None
    if attach_mode == "attach":
        try:
            running_pid = manager.running_pid(app_id) if hasattr(manager, "running_pid") else None
            if running_pid is None:
                checks.append(
                    {
                        "check": "attach-target",
                        "status": "fail",
                        "message": f"{app_id} is not currently running, so attach mode would fail.",
                    }
                )
            else:
                checks.append(
                    {
                        "check": "attach-target",
                        "status": "pass",
                        "message": f"Attach mode can target pid {running_pid}.",
                        "pid": running_pid,
                    }
                )
        except Exception as exc:
            checks.append({"check": "attach-target", "status": "fail", "message": str(exc)})
    else:
        checks.append(
            {
                "check": "spawn-target",
                "status": "pass",
                "message": f"Spawn mode will launch {app_id} through Frida before instrumentation.",
            }
        )

    compatibility = evaluate_runtime_compatibility(
        app_id=app_id,
        device_id=device_id,
        attach_mode=attach_mode,
        session_kind=session_kind,
        application_available=available,
        running_pid=running_pid,
        device=device,
    )
    checks.append(
        {
            "check": "abi",
            "status": "warn",
            "message": "ABI/version compatibility cannot be fully proven ahead of time; reconnect failures will include recovery hints.",
        }
    )
    statuses = [check["status"] for check in checks]
    overall = "fail" if "fail" in statuses else ("warn" if "warn" in statuses else "pass")
    blocked_checks = [str(check["check"]) for check in checks if check["status"] == "fail"]
    warned_checks = [str(check["check"]) for check in checks if check["status"] == "warn"]
    readiness_recommended = compatibility.get("recommended_next_action") or _recommended_action(
        attach_mode=attach_mode,
        overall=overall,
        blocked_checks=blocked_checks,
    )
    runtime_dashboard = {
        "mode": "preflight",
        "status": overall,
        "app_id": app_id,
        "session_kind": session_kind,
        "attach_mode": attach_mode,
        "device_id": device_id,
        "application_available": available,
        "running_pid": running_pid,
        "blocked_checks": blocked_checks,
        "warned_checks": warned_checks,
        "compatibility_warning_count": compatibility.get("warning_count") or 0,
        "compatibility_fail_count": compatibility.get("fail_count") or 0,
        "builtin_script_suggestion_count": len(
            suggest_builtin_runtime_scripts(app_id, session_kind=session_kind)
        ),
        "recommended_next_action": readiness_recommended,
    }
    available_scripts = list_builtin_runtime_scripts()
    suggested_scripts = suggest_builtin_runtime_scripts(app_id, session_kind=session_kind)
    return {
        "app_id": app_id,
        "device_id": device_id,
        "attach_mode": attach_mode,
        "session_kind": session_kind,
        "status": overall,
        "checks": checks,
        "target": {
            "device": device,
            "application_available": available,
            "running_pid": running_pid,
        },
        "compatibility": compatibility,
        "available_builtin_scripts": available_scripts,
        "suggested_builtin_scripts": suggested_scripts,
        "readiness": {
            "status": "blocked"
            if overall == "fail"
            else ("ready-with-warnings" if warned_checks else "ready"),
            "ready": overall != "fail",
            "blocked_checks": blocked_checks,
            "warned_checks": warned_checks,
            "recommended_action": readiness_recommended,
            "next_actions": _next_actions(
                attach_mode=attach_mode, running_pid=running_pid, overall=overall
            ),
        },
        "runtime_dashboard": runtime_dashboard,
        "recovery_hint": None
        if overall == "pass"
        else "Review the failed/warned checks before launching or reconnecting the session.",
    }


def _recommended_action(*, attach_mode: str, overall: str, blocked_checks: list[str]) -> str:
    if overall == "pass" and attach_mode == "attach":
        return (
            "Attach readiness looks good; reconnect or launch while the target process stays alive."
        )
    if overall == "pass":
        return "Spawn readiness looks good; launch when you are ready for the app to restart under Frida."
    if "attach-target" in blocked_checks:
        return "Open the target app first or switch to spawn mode before retrying attach-mode runtime work."
    return "Clear the failed checks before starting or reconnecting a managed runtime session."


def _next_actions(
    *, attach_mode: str, running_pid: int | None, overall: str
) -> list[dict[str, str]]:
    actions = []
    if attach_mode == "attach":
        actions.append(
            {
                "action": "launch-target-app",
                "status": "ready" if running_pid is not None else "blocked",
                "message": (
                    f"Target process is already visible as pid {running_pid}."
                    if running_pid is not None
                    else "Launch the app on-device so attach mode has a live process to bind to."
                ),
            }
        )
        actions.append(
            {
                "action": "reconnect-session",
                "status": "ready" if overall == "pass" else "blocked",
                "message": "Reconnect once the attach target and compatibility checks are clean.",
            }
        )
    else:
        actions.append(
            {
                "action": "launch-managed-session",
                "status": "ready" if overall != "fail" else "blocked",
                "message": "Spawn mode will relaunch the target under Frida before loading the runtime script.",
            }
        )
    return actions
