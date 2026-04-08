from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast


def handle(app: Any, action: str, params: dict[str, Any], *, cb: Any) -> dict[str, Any] | None:
    _ok = cast(Callable[[Any, str], dict[str, Any]], cb._ok)
    _err = cast(Callable[[str], dict[str, Any]], cb._err)
    _opt = cb._opt
    _bool_param = cb._bool_param
    plugin_inventory = cb.plugin_inventory

    if action == "plugins.list":
        out_format = _opt(params.get("format")) or "text"
        reload = _bool_param(params.get("reload")) or False
        payload = plugin_inventory(reload=reload)
        if out_format.lower() == "json":
            return _ok(
                payload,
                f"Plugin inventory: {payload.get('loaded', 0)} loaded, {payload.get('failures', 0)} failures",
            )
        # Text format rendering
        loaded = payload.get("loaded", [])
        failures = payload.get("failures", [])
        lines = [
            f"Plugin API version: {payload.get('api_version')}",
            f"Loaded plugins: {len(loaded)}",
            f"Failed plugins: {len(failures)}",
        ]
        for item in loaded:
            metadata = item.get("metadata", {})
            commands = ", ".join(item.get("commands", [])) or "-"
            lines.append(
                f"- {metadata.get('name')} v{metadata.get('version')} [{item.get('source')}] commands={commands}"
            )
        for item in failures:
            lines.append(f"- FAILED {item.get('source')}: {item.get('error')}")
        text_output = "\n".join(lines)
        return _ok(
            {"text": text_output, **payload},
            f"Plugin inventory: {len(loaded)} loaded, {len(failures)} failures",
        )

    return None
