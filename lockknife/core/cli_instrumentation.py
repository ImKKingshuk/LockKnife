from __future__ import annotations

import time
from dataclasses import asdict
from typing import Any

import click

from lockknife.core.error_report import capture
from lockknife.core.exceptions import LockKnifeError
from lockknife.core.logging import get_logger


def _safe_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        if len(value) > 256:
            return value[:256] + "…"
        return value
    if hasattr(value, "name") and isinstance(value.name, str):
        return value.name
    return type(value).__name__


def _device_hint(params: dict[str, Any]) -> str | None:
    for key in ("serial", "device_id"):
        value = params.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


class LockKnifeCommand(click.Command):
    def invoke(self, ctx: click.Context) -> Any:
        log = get_logger()
        start = time.perf_counter()
        params = {k: _safe_value(v) for k, v in (ctx.params or {}).items()}
        log.info("cli_start", command=ctx.command_path, params=params)
        try:
            out = super().invoke(ctx)
        except click.ClickException:
            log.error(
                "cli_error",
                command=ctx.command_path,
                elapsed_s=round(time.perf_counter() - start, 6),
                exc_info=True,
            )
            raise
        except LockKnifeError as exc:
            log.error(
                "cli_error",
                command=ctx.command_path,
                elapsed_s=round(time.perf_counter() - start, 6),
                error=str(exc),
                exc_info=True,
            )
            raise click.ClickException(str(exc)) from exc
        except Exception:
            report = capture(
                ctx.command_path,
                device_serial=_device_hint(ctx.params or {}),
                extra={"params": params},
            )
            log.error(
                "cli_error",
                command=ctx.command_path,
                elapsed_s=round(time.perf_counter() - start, 6),
                report=asdict(report),
                exc_info=True,
            )
            raise click.ClickException(
                f"Unexpected error while running {ctx.command_path}"
            ) from None
        log.info(
            "cli_done", command=ctx.command_path, elapsed_s=round(time.perf_counter() - start, 6)
        )
        return out


class LockKnifeGroup(click.Group):
    command_class = LockKnifeCommand

    def _ensure_plugin_commands(self) -> None:
        from lockknife.core.plugin_loader import attach_plugin_commands

        attach_plugin_commands(self)

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        self._ensure_plugin_commands()
        return super().get_command(ctx, cmd_name)

    def list_commands(self, ctx: click.Context) -> list[str]:
        self._ensure_plugin_commands()
        return super().list_commands(ctx)
