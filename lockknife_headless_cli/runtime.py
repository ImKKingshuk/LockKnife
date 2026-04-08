from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
import time
from typing import Any

import click

from lockknife.core.case import case_output_path, register_case_artifact
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.cli_types import READABLE_FILE
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules.runtime.frida_manager import FridaManager
from lockknife.modules.runtime.hooks import (
    builtin_runtime_script_choices,
    get_builtin_runtime_script,
)
from lockknife.modules.runtime.memory import heap_dump, memory_search
from lockknife.modules.runtime.tracer import method_tracer_script


@click.group(help="Runtime instrumentation (Frida-based).", cls=LockKnifeGroup)
def runtime() -> None:
    pass


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "runtime"


def _runtime_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _resolve_case_output(
    output: pathlib.Path | None, case_dir: pathlib.Path | None, *, filename: str
) -> tuple[pathlib.Path | None, bool]:
    if output is not None:
        return output, False
    if case_dir is None:
        return None, False
    return case_output_path(case_dir, area="derived", filename=filename), True


def _register_runtime_output(
    *,
    case_dir: pathlib.Path | None,
    path: pathlib.Path,
    category: str,
    source_command: str,
    device_id: str | None,
    input_paths: list[str] | None = None,
    parent_artifact_ids: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> str | None:
    if case_dir is None:
        return None
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
    return artifact.artifact_id


def _run_runtime_session(
    *,
    app_id: str,
    session_kind: str,
    source_command: str,
    script_source: str,
    device_id: str | None,
    case_dir: pathlib.Path | None,
    input_paths: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    mgr = FridaManager(device_id=device_id)
    handle, session = mgr.spawn_and_attach(app_id)
    safe_app_id = _safe_name(app_id)
    safe_kind = _safe_name(session_kind)
    script_artifact_id: str | None = None
    script_snapshot_path: pathlib.Path | None = None
    log_path: pathlib.Path | None = None
    session_path: pathlib.Path | None = None
    session_payload: dict[str, Any] = {
        "app_id": app_id,
        "session_kind": session_kind,
        "device_id": device_id,
        "pid": getattr(handle, "pid", handle if isinstance(handle, int) else None),
        "started_at_utc": _runtime_now(),
        "status": "running",
    }
    if metadata:
        session_payload.update(metadata)

    if case_dir is not None:
        script_snapshot_path = case_output_path(
            case_dir, area="derived", filename=f"runtime_{safe_kind}_{safe_app_id}_script.js"
        )
        script_snapshot_path.write_text(script_source, encoding="utf-8")
        script_artifact_id = _register_runtime_output(
            case_dir=case_dir,
            path=script_snapshot_path,
            category="runtime-script",
            source_command=source_command,
            device_id=device_id,
            input_paths=input_paths,
            metadata={"app_id": app_id, "session_kind": session_kind},
        )
        log_path = case_output_path(
            case_dir, area="logs", filename=f"runtime_{safe_kind}_{safe_app_id}.jsonl"
        )
        log_path.write_text("", encoding="utf-8")
        session_path = case_output_path(
            case_dir, area="derived", filename=f"runtime_{safe_kind}_{safe_app_id}_session.json"
        )
        session_payload.update(
            {
                "log_path": str(log_path),
                "script_snapshot_path": str(script_snapshot_path),
            }
        )

    script = mgr.load_script(session, script_source)

    def on_message(message: dict[str, Any], _data: Any) -> None:
        console.print(str(message))
        if log_path is not None:
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps({"received_at_utc": _runtime_now(), "message": message}, default=str)
                    + "\n"
                )

    script.on("message", on_message)
    console.print("Running. Press Ctrl+C to stop.")
    status = "completed"
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        status = "interrupted"
        return
    finally:
        if case_dir is not None and log_path is not None and session_path is not None:
            session_payload["status"] = status
            session_payload["ended_at_utc"] = _runtime_now()
            session_payload["message_log_path"] = str(log_path)
            write_json(session_path, session_payload)
            log_artifact_id = _register_runtime_output(
                case_dir=case_dir,
                path=log_path,
                category="runtime-session-log",
                source_command=source_command,
                device_id=device_id,
                parent_artifact_ids=[script_artifact_id] if script_artifact_id else None,
                metadata={"app_id": app_id, "session_kind": session_kind},
            )
            parent_ids = [
                artifact_id
                for artifact_id in (script_artifact_id, log_artifact_id)
                if artifact_id is not None
            ]
            _register_runtime_output(
                case_dir=case_dir,
                path=session_path,
                category="runtime-session",
                source_command=source_command,
                device_id=device_id,
                parent_artifact_ids=parent_ids or None,
                metadata={"app_id": app_id, "session_kind": session_kind, "status": status},
            )


@runtime.command("hook")
@click.argument("app_id")
@click.option("--script", "script_path", type=READABLE_FILE, required=True)
@click.option("--device-id")
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def hook_cmd(
    app_id: str, script_path: pathlib.Path, device_id: str | None, case_dir: pathlib.Path | None
) -> None:
    source = script_path.read_text(encoding="utf-8")
    _run_runtime_session(
        app_id=app_id,
        session_kind="hook",
        source_command="runtime hook",
        script_source=source,
        device_id=device_id,
        case_dir=case_dir,
        input_paths=[str(script_path)],
        metadata={"source_script_path": str(script_path)},
    )


@runtime.command("bypass-ssl")
@click.argument("app_id")
@click.option("--device-id")
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def bypass_ssl_cmd(app_id: str, device_id: str | None, case_dir: pathlib.Path | None) -> None:
    script = get_builtin_runtime_script("ssl_bypass")
    _run_runtime_session(
        app_id=app_id,
        session_kind="bypass_ssl",
        source_command="runtime bypass-ssl",
        script_source=str(script["source"]),
        device_id=device_id,
        case_dir=case_dir,
        input_paths=[str(script["path"])],
        metadata={"builtin_script": script["name"], "builtin_category": script["category"]},
    )


@runtime.command("bypass-root")
@click.argument("app_id")
@click.option("--device-id")
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def bypass_root_cmd(app_id: str, device_id: str | None, case_dir: pathlib.Path | None) -> None:
    script = get_builtin_runtime_script("root_bypass")
    _run_runtime_session(
        app_id=app_id,
        session_kind="bypass_root",
        source_command="runtime bypass-root",
        script_source=str(script["source"]),
        device_id=device_id,
        case_dir=case_dir,
        input_paths=[str(script["path"])],
        metadata={"builtin_script": script["name"], "builtin_category": script["category"]},
    )


@runtime.command("trace")
@click.argument("app_id")
@click.option("--class", "class_name", required=True)
@click.option("--method")
@click.option("--device-id")
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def trace_cmd(
    app_id: str,
    class_name: str,
    method: str | None,
    device_id: str | None,
    case_dir: pathlib.Path | None,
) -> None:
    _run_runtime_session(
        app_id=app_id,
        session_kind="trace",
        source_command="runtime trace",
        script_source=method_tracer_script(class_name, method),
        device_id=device_id,
        case_dir=case_dir,
        metadata={"class_name": class_name, "method": method},
    )


@runtime.command("builtin-script")
@click.argument("app_id")
@click.option(
    "--name",
    "builtin_script",
    type=click.Choice(builtin_runtime_script_choices(), case_sensitive=False),
    required=True,
)
@click.option("--device-id")
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def builtin_script_cmd(
    app_id: str, builtin_script: str, device_id: str | None, case_dir: pathlib.Path | None
) -> None:
    script = get_builtin_runtime_script(builtin_script)
    _run_runtime_session(
        app_id=app_id,
        session_kind=str(script["name"]),
        source_command="runtime builtin-script",
        script_source=str(script["source"]),
        device_id=device_id,
        case_dir=case_dir,
        input_paths=[str(script["path"])],
        metadata={"builtin_script": script["name"], "builtin_category": script["category"]},
    )


@runtime.command("memory-search")
@click.argument("app_id")
@click.option("--pattern", required=True)
@click.option("--hex", "is_hex", is_flag=True, default=False)
@click.option("--protection", default="r--")
@click.option("--timeout", "timeout_s", type=float, default=30.0)
@click.option("--device-id")
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def memory_search_cmd(
    app_id: str,
    pattern: str,
    is_hex: bool,
    protection: str,
    timeout_s: float,
    device_id: str | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    pat = f"hex:{pattern}" if is_hex else pattern
    raw = memory_search(
        app_id, pat, device_id=device_id, protection=protection, timeout_s=timeout_s
    )
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"runtime_memory_search_{_safe_name(app_id)}.json"
    )
    if output is not None:
        payload = json.loads(raw)
        write_json(output, payload)
        _register_runtime_output(
            case_dir=case_dir,
            path=output,
            category="runtime-memory-search",
            source_command="runtime memory-search",
            device_id=device_id,
            metadata={
                "app_id": app_id,
                "pattern": pat,
                "protection": protection,
                "timeout_s": timeout_s,
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print(raw)


@runtime.command("heap-dump")
@click.argument("app_id")
@click.option("--output-path", default="/sdcard/lockknife.hprof")
@click.option("--timeout", "timeout_s", type=float, default=30.0)
@click.option("--device-id")
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def heap_dump_cmd(
    app_id: str,
    output_path: str,
    timeout_s: float,
    device_id: str | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    raw = heap_dump(app_id, output_path, device_id=device_id, timeout_s=timeout_s)
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"runtime_heap_dump_{_safe_name(app_id)}.json"
    )
    if output is not None:
        payload = json.loads(raw)
        write_json(output, payload)
        _register_runtime_output(
            case_dir=case_dir,
            path=output,
            category="runtime-heap-dump",
            source_command="runtime heap-dump",
            device_id=device_id,
            metadata={"app_id": app_id, "remote_output_path": output_path, "timeout_s": timeout_s},
        )
        if derived:
            console.print(str(output))
        return
    console.print(raw)
