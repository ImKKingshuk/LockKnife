from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

import click

from lockknife.core.serialize import write_csv, write_json


def register(extract: Any, cli: Any) -> None:
    @extract.command("messaging")
    @click.option("-s", "--serial", required=True)
    @click.option(
        "--app",
        "app_name",
        type=click.Choice(["whatsapp", "telegram", "signal"], case_sensitive=False),
        default="whatsapp",
    )
    @click.option(
        "--mode",
        type=click.Choice(["messages", "artifacts"], case_sensitive=False),
        default="messages",
    )
    @click.option("--limit", type=int, default=500)
    @click.option(
        "--format",
        "out_format",
        type=click.Choice(["json", "csv"], case_sensitive=False),
        default="json",
    )
    @click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
    @click.option(
        "--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path)
    )
    @click.pass_obj
    def extract_messaging_cmd(
        app: Any,
        serial: str,
        app_name: str,
        mode: str,
        limit: int,
        out_format: str,
        output: pathlib.Path | None,
        case_dir: pathlib.Path | None,
    ) -> None:
        app_l = app_name.lower()
        mode_l = mode.lower()
        ext = "csv" if out_format.lower() == "csv" else "json"
        filename = f"messaging_{app_l}_{mode_l}.{ext}"
        output, derived = cli._resolve_case_output(output, case_dir, filename=filename)

        if mode_l == "artifacts":
            if ext != "json":
                raise click.ClickException("--format csv is not supported for --mode artifacts")
            if app_l == "whatsapp":
                payload = dataclasses.asdict(cli.extract_whatsapp_artifacts(app.devices, serial))
            elif app_l == "telegram":
                payload = dataclasses.asdict(cli.extract_telegram_artifacts(app.devices, serial))
            else:
                payload = dataclasses.asdict(cli.extract_signal_artifacts(app.devices, serial))
            if output:
                write_json(output, payload)
                cli._register_output(
                    case_dir=case_dir,
                    output=output,
                    category="extract-messaging",
                    source_command="extract messaging",
                    device_serial=serial,
                    metadata={"app": app_l, "mode": mode_l, "format": ext, "limit": limit},
                )
                if derived:
                    cli.console.print(str(output))
                return
            cli.console.print_json(json.dumps(payload))
            return

        if app_l == "whatsapp":
            rows: list[Any] = cli.extract_whatsapp_messages(app.devices, serial, limit=limit)
        elif app_l == "telegram":
            rows = cli.extract_telegram_messages(app.devices, serial, limit=limit)
        else:
            rows = cli.extract_signal_messages(app.devices, serial, limit=limit)

        items = [dataclasses.asdict(row) for row in rows]
        if output:
            if ext == "csv":
                write_csv(output, items)
            else:
                write_json(output, items)
            cli._register_output(
                case_dir=case_dir,
                output=output,
                category="extract-messaging",
                source_command="extract messaging",
                device_serial=serial,
                metadata={"app": app_l, "mode": mode_l, "format": ext, "limit": limit},
            )
            if derived:
                cli.console.print(str(output))
            return
        cli.console.print_json(json.dumps(items))
