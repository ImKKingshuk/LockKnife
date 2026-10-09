from __future__ import annotations

import json
import sys
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
    hint = data.get("hint")
    if isinstance(error, str) and error and isinstance(hint, str) and hint:
        return f"{error} -> {hint}"
    if isinstance(error, str) and error:
        return error
    if isinstance(hint, str) and hint:
        return hint
    return None


def _render_text(payload: dict[str, Any]) -> str:
    lines: list[str] = [f"Overall: {'OK' if payload.get('ok') else 'FAIL'}"]
    if "full_ok" in payload:
        lines.append(f"Full profile: {'OK' if payload.get('full_ok') else 'INCOMPLETE'}")

    env = payload.get("environment")
    if isinstance(env, dict):
        lines.append("")
        lines.append("Environment:")
        py_exe = env.get("python_executable") or sys.executable
        py_ver = env.get("python_version") or sys.version.split()[0]
        lines.append(f"- Python: {py_ver} ({py_exe})")
        if env.get("is_venv"):
            lines.append(f"- Virtual environment: Active ({env.get('prefix')})")
        else:
            lines.append(f"- Environment: System / Non-venv ({env.get('prefix')})")
        fallbacks = env.get("fallback_paths") or []
        if fallbacks:
            lines.append(f"- Fallback site-packages: {', '.join(fallbacks)}")

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

    if payload.get("full_ok") is False:
        lines.append("")
        lines.append(
            "Tip: Run 'lockknife doctor --install-missing' to automatically install missing optional dependencies."
        )

    return "\n".join(lines)


def _emit(payload: dict[str, Any], out_format: str) -> None:
    if out_format == "json":
        console.print_json(json.dumps(payload))
        return
    text = _render_text(payload)
    try:
        console.print(text, markup=False)
    except TypeError:
        console.print(text)


@click.command("health", cls=LockKnifeCommand, help="Run core environment health checks.")
@click.option(
    "--format",
    "out_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
)
@click.option(
    "--strict", is_flag=True, default=False, help="Exit non-zero when core health checks fail."
)
def health_cmd(out_format: str, strict: bool) -> None:
    payload = health_status()
    _emit(payload, out_format.lower())
    if strict and not payload.get("ok"):
        click.get_current_context().exit(1)


@click.command(
    "doctor", cls=LockKnifeCommand, help="Run extended dependency and configuration diagnostics."
)
@click.option(
    "--format",
    "out_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
)
@click.option(
    "--strict", is_flag=True, default=False, help="Exit non-zero when core health checks fail."
)
@click.option(
    "--install-missing",
    is_flag=True,
    default=False,
    help="Automatically install missing optional dependencies into the active environment.",
)
@click.option(
    "--install-all",
    is_flag=True,
    default=False,
    help="Automatically install all optional LockKnife extras into the active environment.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Display the installation command without executing it.",
)
def doctor_cmd(
    out_format: str,
    strict: bool,
    install_missing: bool = False,
    install_all: bool = False,
    dry_run: bool = False,
) -> None:
    if install_missing or install_all:
        from lockknife.core.health import install_missing_dependencies

        res = install_missing_dependencies(all_extras=install_all, dry_run=dry_run)
        if out_format.lower() == "json":
            console.print_json(json.dumps(res))
        else:
            if res.get("dry_run"):
                console.print(f"[yellow]{res.get('message')}[/yellow]")
            elif res.get("ok"):
                console.print(f"[green]{res.get('message')}[/green]")
            else:
                console.print(f"[red]{res.get('message')}[/red]")

        if not dry_run and res.get("ok") and res.get("installed"):
            console.print("")
            payload = doctor_status()
            _emit(payload, out_format.lower())
            return
        if not res.get("ok") and not dry_run:
            if strict:
                click.get_current_context().exit(1)
            return
        if dry_run:
            return

    payload = doctor_status()
    _emit(payload, out_format.lower())
    if strict and not payload.get("ok"):
        click.get_current_context().exit(1)
