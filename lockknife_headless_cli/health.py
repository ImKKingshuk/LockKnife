from __future__ import annotations

import json
from typing import Any

import click

from lockknife.core.cli_instrumentation import LockKnifeCommand
from lockknife.core.health import doctor_status, health_status
from lockknife.core.output import console


def _detail(data: dict[str, Any]) -> str | None:
    if data.get("installed") is True and data.get("configured") is True:
        return "installed + configured"
    if data.get("installed") is True and data.get("configured") is False:
        return "installed, not configured"
    if data.get("configured") is True and "installed" not in data:
        return "configured"
    path = data.get("path")
    if isinstance(path, str) and path:
        return f"path={path}"
    error = data.get("error")
    if isinstance(error, str) and error:
        return error
    hint = data.get("hint")
    if isinstance(hint, str) and hint:
        return hint
    return None


def _render_text(payload: dict[str, Any]) -> str:
    lines = [f"Overall: {'OK' if payload.get('ok') else 'FAIL'}"]
    if "full_ok" in payload:
        lines.append(f"Full profile: {'OK' if payload.get('full_ok') else 'INCOMPLETE'}")
    for section_name in ("checks", "optional"):
        section = payload.get(section_name)
        if not isinstance(section, dict) or not section:
            continue
        lines.append("")
        lines.append(f"{section_name.title()}:")
        for name, raw in section.items():
            if not isinstance(raw, dict):
                lines.append(f"- {name}: {raw}")
                continue
            status = "OK" if raw.get("ok") else "FAIL"
            detail = _detail(raw)
            suffix = f" ({detail})" if detail else ""
            lines.append(f"- {name}: {status}{suffix}")
    return "\n".join(lines)


def _emit(payload: dict[str, Any], out_format: str) -> None:
    if out_format == "json":
        console.print_json(json.dumps(payload))
        return
    console.print(_render_text(payload))


@click.command("health", cls=LockKnifeCommand, help="Run core environment health checks.")
@click.option("--format", "out_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
@click.option("--strict", is_flag=True, default=False, help="Exit non-zero when core health checks fail.")
def health_cmd(out_format: str, strict: bool) -> None:
    payload = health_status()
    _emit(payload, out_format.lower())
    if strict and not payload.get("ok"):
        click.get_current_context().exit(1)


@click.command("doctor", cls=LockKnifeCommand, help="Run extended dependency and configuration diagnostics.")
@click.option("--format", "out_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text")
@click.option("--strict", is_flag=True, default=False, help="Exit non-zero when core health checks fail.")
def doctor_cmd(out_format: str, strict: bool) -> None:
    payload = doctor_status()
    _emit(payload, out_format.lower())
    if strict and not payload.get("ok"):
        click.get_current_context().exit(1)