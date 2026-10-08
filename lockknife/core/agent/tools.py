from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import pathlib
import time
from collections.abc import Callable
from typing import Any

from lockknife.core.adb import AdbClient
from lockknife.core.agent.exec_session import ExecSessionManager
from lockknife.core.agent.models import ToolInvocation, ToolObservation

logger = logging.getLogger("lockknife.agent.tools")


class AgentToolRegistry:
    """Manages tool specifications and execution across LockKnife capabilities."""

    def __init__(
        self,
        *,
        case_dir: pathlib.Path,
        target_serial: str | None = None,
        action_callback: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
        subagent_manager: Any | None = None,
        memory_store: Any | None = None,
        exec_session_manager: ExecSessionManager | None = None,
    ) -> None:
        self.case_dir = pathlib.Path(case_dir).resolve()
        self.target_serial = target_serial
        self._action_callback = action_callback
        self.subagent_manager = subagent_manager
        self.memory_store = memory_store
        self.exec_sessions = exec_session_manager or ExecSessionManager()
        self._adb_client: AdbClient | None = None
        self._tool_specs_cache: list[dict[str, Any]] | None = None

    def _get_adb(self) -> AdbClient:
        if self._adb_client is None:
            self._adb_client = AdbClient()
        return self._adb_client

    def _get_action_callback(self) -> Callable[[str, dict[str, Any]], dict[str, Any]]:
        if self._action_callback is None:
            try:
                from lockknife_headless_cli.tui_callback import build_tui_callback

                self._action_callback = build_tui_callback(None)
            except Exception as exc:
                err_msg = str(exc)
                logger.error("Failed to load tui_callback: %s", err_msg)

                def _fallback_cb(action: str, params: dict[str, Any]) -> dict[str, Any]:
                    return {"ok": False, "error": f"Action callback unavailable: {err_msg}"}

                self._action_callback = _fallback_cb
        return self._action_callback

    def get_tool_specs(self) -> list[dict[str, Any]]:
        """Return all available tools formatted as OpenAI Function tools."""
        if self._tool_specs_cache is not None:
            return self._tool_specs_cache

        specs: list[dict[str, Any]] = []

        # 1. Forensic & Agent Primitives
        specs.append({
            "type": "function",
            "function": {
                "name": "device_shell",
                "description": "Execute a raw shell command on the connected Android target via ADB.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The shell command to run on device (e.g. 'getprop ro.build.version.release', 'pm list packages').",
                        },
                        "serial": {
                            "type": "string",
                            "description": "Target device serial (optional, uses active device if omitted).",
                        },
                    },
                    "required": ["command"],
                },
            },
        })

        specs.append({
            "type": "function",
            "function": {
                "name": "case_read_file",
                "description": "Read the contents of an artifact, SQLite export, log, or note inside the case workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "relative_path": {
                            "type": "string",
                            "description": "Path relative to the case workspace root (e.g. 'evidence/sms.json', '.agent/facts.json').",
                        },
                    },
                    "required": ["relative_path"],
                },
            },
        })

        specs.append({
            "type": "function",
            "function": {
                "name": "case_write_file",
                "description": "Write investigator notes, decoded payloads, or extracted evidence to the case workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "relative_path": {
                            "type": "string",
                            "description": "Path relative to case workspace root (e.g. 'notes/findings.md').",
                        },
                        "content": {
                            "type": "string",
                            "description": "Text content to save.",
                        },
                    },
                    "required": ["relative_path", "content"],
                },
            },
        })

        specs.append({
            "type": "function",
            "function": {
                "name": "record_fact",
                "description": "Store a discovered persistent semantic fact (e.g. Android version, vulnerable app, extracted key) into case memory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string", "description": "Key name (e.g. 'target_os', 'package_name', 'cve_found')."},
                        "value": {"type": "string", "description": "Fact value or JSON string."},
                    },
                    "required": ["key", "value"],
                },
            },
        })

        specs.append({
            "type": "function",
            "function": {
                "name": "delegate_subagent",
                "description": "Spawn an autonomous subagent for a focused, parallel deep-dive investigation.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "objective": {
                            "type": "string",
                            "description": "Specific sub-mission objective for the delegate agent.",
                        },
                        "target_device": {
                            "type": "string",
                            "description": "Optional specific device serial for the subagent.",
                        },
                        "budget_iterations": {
                            "type": "integer",
                            "description": "Maximum turn budget for subagent (default: 10).",
                        },
                    },
                    "required": ["objective"],
                },
            },
        })

        specs.append({
            "type": "function",
            "function": {
                "name": "exec_session_start",
                "description": "Start a persistent, stateful interactive background process (e.g. interactive shell, logcat stream, tcpdump).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "The command line string to run."},
                        "session_id": {"type": "string", "description": "Optional custom session ID."},
                    },
                    "required": ["command"],
                },
            },
        })

        specs.append({
            "type": "function",
            "function": {
                "name": "exec_session_write",
                "description": "Send stdin input text to an active interactive background session.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Target session ID."},
                        "input_text": {"type": "string", "description": "Input text to write to process stdin."},
                    },
                    "required": ["session_id", "input_text"],
                },
            },
        })

        specs.append({
            "type": "function",
            "function": {
                "name": "exec_session_poll",
                "description": "Poll and drain buffered output lines from an active background session.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Target session ID."},
                        "wait_s": {"type": "number", "description": "Seconds to wait for new output (default: 0.5)."},
                    },
                    "required": ["session_id"],
                },
            },
        })

        specs.append({
            "type": "function",
            "function": {
                "name": "exec_session_close",
                "description": "Terminate an active background session cleanly.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Target session ID to close."},
                    },
                    "required": ["session_id"],
                },
            },
        })

        # 2. Dynamic LockKnife Action Catalog
        try:
            from lockknife_headless_cli.actions.metadata import load_action_metadata

            metadata = load_action_metadata()
            for action_id, meta in metadata.items():
                # Avoid collision with primitive names
                if action_id in {"device_shell", "case_read_file", "case_write_file"}:
                    continue

                properties: dict[str, Any] = {}
                required_fields: list[str] = []

                for field in meta.get("fields", []):
                    key = field["key"]
                    kind = field.get("kind", "text")
                    desc = field.get("label", key)

                    prop_type = "string"
                    if kind == "number":
                        prop_type = "number"
                    elif kind == "bool":
                        prop_type = "boolean"
                    elif kind == "json":
                        prop_type = "object"

                    prop: dict[str, Any] = {"type": prop_type, "description": desc}
                    if field.get("choices"):
                        prop["enum"] = field["choices"]
                    if field.get("default") is not None:
                        prop["default"] = field["default"]

                    properties[key] = prop
                    if field.get("required"):
                        required_fields.append(key)

                specs.append({
                    "type": "function",
                    "function": {
                        "name": action_id,
                        "description": meta.get("description") or f"LockKnife capability: {meta.get('label', action_id)}",
                        "parameters": {
                            "type": "object",
                            "properties": properties,
                            "required": required_fields,
                        },
                    },
                })
        except Exception as exc:
            logger.warning("Could not load dynamic action catalog metadata: %s", exc)

        self._tool_specs_cache = specs
        return specs

    def execute(self, invocation: ToolInvocation) -> ToolObservation:
        """Execute a tool invocation and capture timing and observation."""
        tool_id = invocation.tool_id
        args = invocation.arguments
        start_time = time.perf_counter()

        try:
            # 1. Primitives
            if tool_id == "device_shell":
                cmd = str(args.get("command") or "").strip()
                serial = str(args.get("serial") or self.target_serial or "").strip()
                if not cmd:
                    return ToolObservation(
                        call_id=invocation.call_id,
                        tool_id=tool_id,
                        success=False,
                        error="Missing 'command' argument",
                        duration_s=time.perf_counter() - start_time,
                    )
                out = self._get_adb().shell(serial=serial, command=cmd) if serial else self._get_adb().run(["shell", cmd])
                return ToolObservation(
                    call_id=invocation.call_id,
                    tool_id=tool_id,
                    success=True,
                    output=out.strip(),
                    duration_s=time.perf_counter() - start_time,
                )

            if tool_id == "case_read_file":
                rel = str(args.get("relative_path") or "").strip().lstrip("/")
                target = (self.case_dir / rel).resolve()
                if not str(target).startswith(str(self.case_dir)):
                    return ToolObservation(
                        call_id=invocation.call_id,
                        tool_id=tool_id,
                        success=False,
                        error=f"Access denied: path {rel} escapes case workspace",
                        duration_s=time.perf_counter() - start_time,
                    )
                if not target.exists():
                    return ToolObservation(
                        call_id=invocation.call_id,
                        tool_id=tool_id,
                        success=False,
                        error=f"File not found: {rel}",
                        duration_s=time.perf_counter() - start_time,
                    )
                content = target.read_text(encoding="utf-8", errors="replace")
                return ToolObservation(
                    call_id=invocation.call_id,
                    tool_id=tool_id,
                    success=True,
                    output=content,
                    duration_s=time.perf_counter() - start_time,
                )

            if tool_id == "case_write_file":
                rel = str(args.get("relative_path") or "").strip().lstrip("/")
                content = str(args.get("content") or "")
                target = (self.case_dir / rel).resolve()
                if not str(target).startswith(str(self.case_dir)):
                    return ToolObservation(
                        call_id=invocation.call_id,
                        tool_id=tool_id,
                        success=False,
                        error=f"Access denied: path {rel} escapes case workspace",
                        duration_s=time.perf_counter() - start_time,
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
                return ToolObservation(
                    call_id=invocation.call_id,
                    tool_id=tool_id,
                    success=True,
                    output=f"Successfully written {len(content)} bytes to {rel}",
                    duration_s=time.perf_counter() - start_time,
                    artifacts_created=[str(target)],
                )

            if tool_id == "record_fact":
                key = str(args.get("key") or "").strip()
                val = args.get("value")
                if self.memory_store is not None:
                    self.memory_store.set_fact(key, val)
                return ToolObservation(
                    call_id=invocation.call_id,
                    tool_id=tool_id,
                    success=True,
                    output=f"Stored semantic fact: {key} = {val}",
                    duration_s=time.perf_counter() - start_time,
                )

            if tool_id == "delegate_subagent":
                if self.subagent_manager is None:
                    return ToolObservation(
                        call_id=invocation.call_id,
                        tool_id=tool_id,
                        success=False,
                        error="Subagent delegation manager is not configured in this runtime",
                        duration_s=time.perf_counter() - start_time,
                    )
                sub_res = self.subagent_manager.spawn_and_run(
                    objective=str(args.get("objective") or ""),
                    target_device=str(args.get("target_device") or self.target_serial or "") or None,
                    budget_iterations=int(args.get("budget_iterations", 10)),
                )
                return ToolObservation(
                    call_id=invocation.call_id,
                    tool_id=tool_id,
                    success=sub_res.status.value == "completed",
                    output=sub_res.to_dict(),
                    duration_s=time.perf_counter() - start_time,
                    artifacts_created=sub_res.artifacts_created,
                )

            if tool_id == "exec_session_start":
                cmd = str(args.get("command") or "").strip()
                sid = str(args.get("session_id") or "").strip() or None
                res = self.exec_sessions.start_session(command=cmd, session_id=sid)
                return ToolObservation(
                    call_id=invocation.call_id,
                    tool_id=tool_id,
                    success=bool(res.get("ok", False)),
                    output=res,
                    error=res.get("error"),
                    duration_s=time.perf_counter() - start_time,
                )

            if tool_id == "exec_session_write":
                sid = str(args.get("session_id") or "").strip()
                txt = str(args.get("input_text") or "")
                res = self.exec_sessions.write_session(session_id=sid, input_text=txt)
                return ToolObservation(
                    call_id=invocation.call_id,
                    tool_id=tool_id,
                    success=bool(res.get("ok", False)),
                    output=res,
                    error=res.get("error"),
                    duration_s=time.perf_counter() - start_time,
                )

            if tool_id == "exec_session_poll":
                sid = str(args.get("session_id") or "").strip()
                wait_s = float(args.get("wait_s", 0.5))
                res = self.exec_sessions.poll_session(session_id=sid, wait_s=wait_s)
                return ToolObservation(
                    call_id=invocation.call_id,
                    tool_id=tool_id,
                    success=bool(res.get("ok", False)),
                    output=res,
                    error=res.get("error"),
                    duration_s=time.perf_counter() - start_time,
                )

            if tool_id == "exec_session_close":
                sid = str(args.get("session_id") or "").strip()
                res = self.exec_sessions.close_session(session_id=sid)
                return ToolObservation(
                    call_id=invocation.call_id,
                    tool_id=tool_id,
                    success=bool(res.get("ok", False)),
                    output=res,
                    error=res.get("error"),
                    duration_s=time.perf_counter() - start_time,
                )

            # 2. LockKnife Dynamic Action Callback
            cb = self._get_action_callback()
            params = dict(args)
            if "case_dir" not in params:
                params["case_dir"] = str(self.case_dir)
            if self.target_serial and "serial" not in params:
                params["serial"] = self.target_serial

            raw_res = cb(tool_id, params)
            is_ok = bool(raw_res.get("ok", True)) if isinstance(raw_res, dict) else True
            err = raw_res.get("error") if isinstance(raw_res, dict) else None

            return ToolObservation(
                call_id=invocation.call_id,
                tool_id=tool_id,
                success=is_ok,
                output=raw_res,
                error=str(err) if err else None,
                duration_s=time.perf_counter() - start_time,
            )

        except Exception as exc:
            logger.exception("Error executing tool %s: %s", tool_id, exc)
            return ToolObservation(
                call_id=invocation.call_id,
                tool_id=tool_id,
                success=False,
                error=f"Execution error: {exc}",
                duration_s=time.perf_counter() - start_time,
            )

    def execute_batch(
        self,
        invocations: list[ToolInvocation],
        max_concurrency: int = 4,
    ) -> list[ToolObservation]:
        """Execute a batch of tool calls concurrently while preserving invocation order."""
        if not invocations:
            return []
        if len(invocations) == 1 or max_concurrency <= 1:
            return [self.execute(inv) for inv in invocations]

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(invocations), max_concurrency)
        ) as pool:
            futures = [pool.submit(self.execute, inv) for inv in invocations]
            return [f.result() for f in futures]
