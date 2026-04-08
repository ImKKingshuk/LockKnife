from __future__ import annotations

import json
from typing import Any, cast

import click

from lockknife.core.cli_instrumentation import LockKnifeCommand
from lockknife.core.output import console
from lockknife.core.plugin_loader import plugin_inventory


def _dict_items(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [cast(dict[str, Any], item) for item in value if isinstance(item, dict)]


def _render_text(payload: dict[str, object]) -> str:
    loaded = _dict_items(payload.get("loaded"))
    failures = _dict_items(payload.get("failures"))
    lines = [
        f"Plugin API version: {payload.get('api_version')}",
        f"Loaded plugins: {len(loaded)}",
        f"Failed plugins: {len(failures)}",
    ]
    for item in loaded:
        metadata_obj = item.get("metadata")
        metadata = metadata_obj if isinstance(metadata_obj, dict) else {}
        commands_obj = item.get("commands")
        commands = (
            ", ".join(str(command) for command in commands_obj)
            if isinstance(commands_obj, list)
            else ""
        )
        lines.append(
            f"- {metadata.get('name')} v{metadata.get('version')} [{item.get('source')}]"
            f" commands={commands or '-'}"
        )
    for item in failures:
        if isinstance(item, dict):
            lines.append(f"- FAILED {item.get('source')}: {item.get('error')}")
    return "\n".join(lines)


@click.group("plugins", help="Inspect externally discovered LockKnife plugins.")
def plugins_group() -> None:
    pass


@plugins_group.command("list", cls=LockKnifeCommand)
@click.option(
    "--format",
    "out_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
)
@click.option(
    "--reload",
    is_flag=True,
    default=False,
    help="Re-discover plugins before rendering the inventory.",
)
def plugins_list(out_format: str, reload: bool) -> None:
    payload = plugin_inventory(reload=reload)
    if out_format.lower() == "json":
        console.print_json(json.dumps(payload))
        return
    console.print(_render_text(payload))
