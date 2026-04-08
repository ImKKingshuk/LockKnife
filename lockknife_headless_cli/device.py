from __future__ import annotations

import json
from typing import Any

import click
from rich.table import Table

from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.output import console


@click.group(help="ADB device management: list, connect, info, shell.", cls=LockKnifeGroup)
def device() -> None:
    pass


@device.command("list")
@click.option(
    "--format", "fmt", type=click.Choice(["table", "json"], case_sensitive=False), default="table"
)
@click.pass_obj
def list_devices(app: Any, fmt: str) -> None:
    handles = app.devices.list_handles()
    if fmt.lower() == "json":
        console.print_json(json.dumps([h.__dict__ for h in handles]))
        return

    table = Table(title="ADB Devices")
    table.add_column("Serial")
    table.add_column("ADB State")
    table.add_column("LK State")
    table.add_column("Model")
    table.add_column("Device")
    table.add_column("Transport")
    for h in handles:
        table.add_row(
            h.serial,
            h.adb_state,
            h.state.value,
            h.model or "",
            h.device or "",
            h.transport_id or "",
        )
    console.print(table)


@device.command("connect")
@click.argument("host")
@click.pass_obj
def connect(app: Any, host: str) -> None:
    out = app.devices.connect_device(host)
    console.print(out)


@device.command("info")
@click.option("-s", "--serial", required=True)
@click.option("--all", "all_devices", is_flag=True, default=False)
@click.option(
    "--format", "fmt", type=click.Choice(["table", "json"], case_sensitive=False), default="table"
)
@click.pass_obj
def info(app: Any, serial: str, all_devices: bool, fmt: str) -> None:
    if all_devices:
        serials = app.devices.authorized_serials()
        results = app.devices.map_devices(lambda s: app.devices.info(s).props, serials=serials)
        if fmt.lower() == "json":
            console.print_json(json.dumps(results))
            return
        for s in serials:
            v = results.get(s)
            table = Table(title=f"Device Info: {s}")
            table.add_column("Property")
            table.add_column("Value")
            if isinstance(v, Exception):
                table.add_row("error", str(v))
            else:
                for k in sorted(v):
                    table.add_row(k, v[k])
            console.print(table)
        return

    info = app.devices.info(serial)
    if fmt.lower() == "json":
        console.print_json(json.dumps(info.props))
        return
    table = Table(title=f"Device Info: {serial}")
    table.add_column("Property")
    table.add_column("Value")
    for k in sorted(info.props):
        table.add_row(k, info.props[k])
    console.print(table)


@device.command("shell")
@click.option("-s", "--serial", required=True)
@click.option("--all", "all_devices", is_flag=True, default=False)
@click.argument("command", nargs=-1, required=True)
@click.pass_obj
def shell(app: Any, serial: str, all_devices: bool, command: tuple[str, ...]) -> None:
    cmd = " ".join(command)
    if all_devices:
        serials = app.devices.authorized_serials()
        results = app.devices.map_devices(
            lambda s: app.adb.shell(s, cmd, timeout_s=120.0), serials=serials
        )
        for s in serials:
            v = results.get(s)
            if isinstance(v, Exception):
                console.print(f"[{s}] error: {v}")
            else:
                for ln in str(v).splitlines():
                    console.print(f"[{s}] {ln}")
        return
    out = app.adb.shell(serial, cmd, timeout_s=120.0)
    console.print(out.rstrip("\n"))
