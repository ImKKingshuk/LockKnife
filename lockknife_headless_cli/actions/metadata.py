"""Load and validate the versioned catalog shared by Python and the native TUI."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any


def load_action_metadata() -> dict[str, dict[str, Any]]:
    raw = json.loads(files(__package__).joinpath("catalog.json").read_text(encoding="utf-8"))
    if raw.get("schema_version") != 1 or not isinstance(raw.get("modules"), list):
        raise ValueError("Unsupported action catalog schema")
    definitions: dict[str, dict[str, Any]] = {}
    module_ids: set[str] = set()
    for module in raw["modules"]:
        module_id = module["id"]
        if not isinstance(module_id, str) or not module_id or module_id in module_ids:
            raise ValueError(f"Invalid or duplicate catalog module: {module_id}")
        module_ids.add(module_id)
        for action in module["actions"]:
            action_id = action["id"]
            if not isinstance(action_id, str) or not action_id or action_id in definitions:
                raise ValueError(f"Invalid or duplicate catalog action: {action_id}")
            keys: set[str] = set()
            for field in action["fields"]:
                key = field["key"]
                if not isinstance(key, str) or not key or key in keys:
                    raise ValueError(f"Invalid or duplicate field in {action_id}: {key}")
                keys.add(key)
                if field["kind"] not in {"text", "number", "bool", "choice", "path", "json"}:
                    raise ValueError(f"Unknown field kind in {action_id}: {field['kind']}")
                choices = field.get("choices", [])
                if not isinstance(choices, list) or any(not isinstance(v, str) for v in choices):
                    raise ValueError(f"Invalid field choices in {action_id}: {key}")
                if field["kind"] == "choice" and field.get("default") not in choices:
                    raise ValueError(f"Choice default is not an option in {action_id}: {key}")
            for flag in ("requires_device", "confirm"):
                if not isinstance(action[flag], bool):
                    raise ValueError(f"Invalid {flag} flag in {action_id}")
            definitions[action_id] = {
                **action,
                "module_id": module_id,
                "module_label": module["label"],
            }
    return definitions
