from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

import click

from lockknife.core.serialize import write_csv, write_json


def register(extract: Any, cli: Any) -> None:
    @extract.command("sms")
    @click.option("-s", "--serial", required=True)
    @click.option("--limit", type=int, default=200)
    @click.option("--format", "out_format", type=click.Choice(["json", "csv"], case_sensitive=False), default="json")
    @click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
    @click.pass_obj
    def extract_sms_cmd(app: Any, serial: str, limit: int, out_format: str, output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
        rows = cli.extract_sms(app.devices, serial, limit=limit)
        items = [dataclasses.asdict(row) for row in rows]
        ext = "csv" if out_format.lower() == "csv" else "json"
        output, derived = cli._resolve_case_output(output, case_dir, filename=f"sms.{ext}")
        if output:
            if ext == "csv":
                write_csv(output, items)
            else:
                write_json(output, items)
            cli._register_output(
                case_dir=case_dir,
                output=output,
                category="extract-sms",
                source_command="extract sms",
                device_serial=serial,
                metadata={"format": ext, "limit": limit},
            )
            if derived:
                cli.console.print(str(output))
            return
        cli.console.print_json(json.dumps(items))

    @extract.command("contacts")
    @click.option("-s", "--serial", required=True)
    @click.option("--limit", type=int, default=500)
    @click.option("--format", "out_format", type=click.Choice(["json", "csv"], case_sensitive=False), default="json")
    @click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
    @click.pass_obj
    def extract_contacts_cmd(app: Any, serial: str, limit: int, out_format: str, output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
        rows = cli.extract_contacts(app.devices, serial, limit=limit)
        items = [dataclasses.asdict(row) for row in rows]
        ext = "csv" if out_format.lower() == "csv" else "json"
        output, derived = cli._resolve_case_output(output, case_dir, filename=f"contacts.{ext}")
        if output:
            if ext == "csv":
                write_csv(output, items)
            else:
                write_json(output, items)
            cli._register_output(
                case_dir=case_dir,
                output=output,
                category="extract-contacts",
                source_command="extract contacts",
                device_serial=serial,
                metadata={"format": ext, "limit": limit},
            )
            if derived:
                cli.console.print(str(output))
            return
        cli.console.print_json(json.dumps(items))

    @extract.command("call-logs")
    @click.option("-s", "--serial", required=True)
    @click.option("--limit", type=int, default=500)
    @click.option("--format", "out_format", type=click.Choice(["json", "csv"], case_sensitive=False), default="json")
    @click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
    @click.pass_obj
    def extract_call_logs_cmd(app: Any, serial: str, limit: int, out_format: str, output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
        rows = cli.extract_call_logs(app.devices, serial, limit=limit)
        items = [dataclasses.asdict(row) for row in rows]
        ext = "csv" if out_format.lower() == "csv" else "json"
        output, derived = cli._resolve_case_output(output, case_dir, filename=f"call_logs.{ext}")
        if output:
            if ext == "csv":
                write_csv(output, items)
            else:
                write_json(output, items)
            cli._register_output(
                case_dir=case_dir,
                output=output,
                category="extract-call-logs",
                source_command="extract call-logs",
                device_serial=serial,
                metadata={"format": ext, "limit": limit},
            )
            if derived:
                cli.console.print(str(output))
            return
        cli.console.print_json(json.dumps(items))
