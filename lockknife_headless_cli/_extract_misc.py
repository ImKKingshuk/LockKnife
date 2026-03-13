from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

import click

from lockknife.core.serialize import write_csv, write_json


def register(extract: Any, cli: Any) -> None:
    @extract.command("media")
    @click.option("-s", "--serial", required=True)
    @click.option("--limit", type=int, default=50)
    @click.option("--format", "out_format", type=click.Choice(["json", "csv"], case_sensitive=False), default="json")
    @click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
    @click.pass_obj
    def extract_media_cmd(app: Any, serial: str, limit: int, out_format: str, output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
        rows = cli.extract_media_with_exif(app.devices, serial, limit=limit)
        items = [dataclasses.asdict(row) for row in rows]
        ext = "csv" if out_format.lower() == "csv" else "json"
        output, derived = cli._resolve_case_output(output, case_dir, filename=f"media.{ext}")
        if output:
            if ext == "csv":
                write_csv(output, items)
            else:
                write_json(output, items)
            cli._register_output(
                case_dir=case_dir,
                output=output,
                category="extract-media",
                source_command="extract media",
                device_serial=serial,
                metadata={"format": ext, "limit": limit},
            )
            if derived:
                cli.console.print(str(output))
            return
        cli.console.print_json(json.dumps(items))

    @extract.command("location")
    @click.option("-s", "--serial", required=True)
    @click.option("--mode", type=click.Choice(["snapshot", "artifacts"], case_sensitive=False), default="snapshot")
    @click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
    @click.pass_obj
    def extract_location_cmd(app: Any, serial: str, mode: str, output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
        output, derived = cli._resolve_case_output(output, case_dir, filename=f"location_{mode.lower()}.json")
        if mode.lower() == "artifacts":
            payload = dataclasses.asdict(cli.extract_location_artifacts(app.devices, serial))
        else:
            payload = dataclasses.asdict(cli.extract_location_snapshot(app.devices, serial))
        if output:
            write_json(output, payload)
            cli._register_output(
                case_dir=case_dir,
                output=output,
                category="extract-location",
                source_command="extract location",
                device_serial=serial,
                metadata={"mode": mode.lower(), "format": "json"},
            )
            if derived:
                cli.console.print(str(output))
            return
        cli.console.print_json(json.dumps(payload))
