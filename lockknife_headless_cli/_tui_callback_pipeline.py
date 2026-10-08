from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast


def _safe_bool(val: Any, default: bool = False) -> bool:
    if val is None or val == "":
        return default
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def handle(app: Any, action: str, params: dict[str, Any], *, cb: Any) -> dict[str, Any] | None:
    pathlib = cb.pathlib
    _ok = cast(Callable[[Any, str], dict[str, Any]], cb._ok)
    _err = cast(Callable[[str], dict[str, Any]], cb._err)
    _opt = cb._opt
    _path_param = cb._path_param

    from lockknife.core.pipeline import (
        PipelineExecutor,
        get_playbook,
        list_playbooks,
        load_custom_playbook,
    )

    if action == "pipeline.list":
        playbooks = list_playbooks()
        data = [p.to_dict() for p in playbooks]
        return _ok(data, f"Loaded {len(data)} investigation playbooks")

    if action == "pipeline.plan":
        playbook_name = params.get("playbook") or "triage"
        recipe_path = _path_param(params.get("recipe"))
        case_dir = _path_param(params.get("case_dir")) or pathlib.Path("./cases/CASE-PREVIEW")
        serial = _opt(params.get("serial"))

        if recipe_path is not None:
            pb = load_custom_playbook(recipe_path)
        else:
            pb = get_playbook(playbook_name)

        executor = PipelineExecutor(case_dir=case_dir, target_serial=serial)
        plan_data = executor.plan(pb)
        return _ok(plan_data, f"Generated execution plan for playbook: {pb.name}")

    if action == "pipeline.run":
        playbook_name = params.get("playbook") or "triage"
        recipe_path = _path_param(params.get("recipe"))
        case_dir = _path_param(params.get("case_dir")) or pathlib.Path("./cases/CASE-001")
        serial = _opt(params.get("serial"))
        stop_on_failure = _safe_bool(params.get("stop_on_failure"), False)
        resume = _safe_bool(params.get("resume"), False)

        if recipe_path is not None:
            pb = load_custom_playbook(recipe_path)
        else:
            pb = get_playbook(playbook_name)

        executor = PipelineExecutor(
            case_dir=case_dir,
            target_serial=serial,
            stop_on_failure=stop_on_failure,
        )
        run_record = executor.execute(pb, resume=resume)
        return _ok(
            run_record.to_dict(),
            f"Playbook {pb.name} executed with status: {run_record.status.value}",
        )

    return None
