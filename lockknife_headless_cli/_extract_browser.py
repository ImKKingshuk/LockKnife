from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

import click

from lockknife.core.serialize import write_csv, write_json


def register(extract: Any, cli: Any) -> None:
    @extract.command("browser")
    @click.option("-s", "--serial", required=True)
    @click.option("--app", "app_name", type=click.Choice(["chrome", "edge", "brave", "opera", "firefox"], case_sensitive=False), default="chrome")
    @click.option(
        "--kind",
        "kind",
        type=click.Choice(["history", "bookmarks", "downloads", "cookies", "passwords", "all"], case_sensitive=False),
        default="history",
    )
    @click.option("--limit", type=int, default=500)
    @click.option("--format", "out_format", type=click.Choice(["json", "csv"], case_sensitive=False), default="json")
    @click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
    @click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
    @click.pass_obj
    def extract_browser_cmd(app: Any, serial: str, app_name: str, kind: str, limit: int, out_format: str, output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
        app_l = app_name.lower()
        kind_l = kind.lower()
        ext = "csv" if out_format.lower() == "csv" else "json"
        filename = f"browser_{app_l}.{ext}" if kind_l == "all" else f"browser_{app_l}_{kind_l}.{ext}"
        output, derived = cli._resolve_case_output(output, case_dir, filename=filename)

        if kind_l == "all":
            if ext != "json":
                raise click.ClickException("--format csv is not supported for --kind all")
            if app_l == "firefox":
                payload = {
                    "app": "firefox",
                    "history": [dataclasses.asdict(row) for row in cli.extract_firefox_history(app.devices, serial, limit=limit)],
                    "bookmarks": [dataclasses.asdict(row) for row in cli.extract_firefox_bookmarks(app.devices, serial, limit=limit)],
                    "passwords": [dataclasses.asdict(row) for row in cli.extract_firefox_saved_logins(app.devices, serial, limit=limit)],
                }
            else:
                payload = {
                    "app": app_l,
                    "history": [dataclasses.asdict(row) for row in cli.extract_chrome_history(app.devices, serial, limit=limit, browser=app_l)],
                    "bookmarks": [dataclasses.asdict(row) for row in cli.extract_chrome_bookmarks(app.devices, serial, limit=limit, browser=app_l)],
                    "downloads": [dataclasses.asdict(row) for row in cli.extract_chrome_downloads(app.devices, serial, limit=limit, browser=app_l)],
                    "cookies": [dataclasses.asdict(row) for row in cli.extract_chrome_cookies(app.devices, serial, limit=limit, browser=app_l)],
                    "passwords": [dataclasses.asdict(row) for row in cli.extract_chrome_saved_logins(app.devices, serial, limit=limit, browser=app_l)],
                }
            if output:
                write_json(output, payload)
                cli._register_output(
                    case_dir=case_dir,
                    output=output,
                    category="extract-browser",
                    source_command="extract browser",
                    device_serial=serial,
                    metadata={"app": app_l, "kind": kind_l, "format": ext, "limit": limit},
                )
                if derived:
                    cli.console.print(str(output))
                return
            cli.console.print_json(json.dumps(payload))
            return

        rows: list[Any]
        if app_l != "firefox":
            if kind_l == "history":
                rows = cli.extract_chrome_history(app.devices, serial, limit=limit, browser=app_l)
            elif kind_l == "bookmarks":
                rows = cli.extract_chrome_bookmarks(app.devices, serial, limit=limit, browser=app_l)
            elif kind_l == "downloads":
                rows = cli.extract_chrome_downloads(app.devices, serial, limit=limit, browser=app_l)
            elif kind_l == "cookies":
                rows = cli.extract_chrome_cookies(app.devices, serial, limit=limit, browser=app_l)
            else:
                rows = cli.extract_chrome_saved_logins(app.devices, serial, limit=limit, browser=app_l)
        else:
            if kind_l == "history":
                rows = cli.extract_firefox_history(app.devices, serial, limit=limit)
            elif kind_l == "bookmarks":
                rows = cli.extract_firefox_bookmarks(app.devices, serial, limit=limit)
            elif kind_l == "passwords":
                rows = cli.extract_firefox_saved_logins(app.devices, serial, limit=limit)
            else:
                rows = []

        items = [dataclasses.asdict(row) for row in rows]
        if output:
            if ext == "csv":
                write_csv(output, items)
            else:
                write_json(output, items)
            cli._register_output(
                case_dir=case_dir,
                output=output,
                category="extract-browser",
                source_command="extract browser",
                device_serial=serial,
                metadata={"app": app_l, "kind": kind_l, "format": ext, "limit": limit},
            )
            if derived:
                cli.console.print(str(output))
            return
        cli.console.print_json(json.dumps(items))
