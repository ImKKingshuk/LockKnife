from __future__ import annotations

import json
import pathlib
from typing import Any

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.pipeline.models import PipelineCheckpoint
from lockknife.core.serialize import write_json


def pipeline_dir(case_dir: pathlib.Path) -> pathlib.Path:
    p = case_dir / "pipelines"
    p.mkdir(parents=True, exist_ok=True)
    return p


def pipeline_checkpoint_path(case_dir: pathlib.Path, pipeline_id: str) -> pathlib.Path:
    return pipeline_dir(case_dir) / f"{pipeline_id}.json"


def save_checkpoint(checkpoint: PipelineCheckpoint) -> pathlib.Path:
    path = pipeline_checkpoint_path(pathlib.Path(checkpoint.case_dir), checkpoint.pipeline_id)
    write_json(path, checkpoint.to_dict())
    return path


def load_checkpoint(case_dir: pathlib.Path, pipeline_id: str) -> PipelineCheckpoint:
    path = pipeline_checkpoint_path(case_dir, pipeline_id)
    if not path.exists():
        raise LockKnifeError(f"Pipeline checkpoint not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError("Expected dictionary payload")
        return PipelineCheckpoint.from_dict(payload)
    except Exception as exc:
        raise LockKnifeError(f"Failed to load pipeline checkpoint {path}: {exc}") from exc


def list_checkpoints(case_dir: pathlib.Path) -> list[PipelineCheckpoint]:
    p_dir = case_dir / "pipelines"
    if not p_dir.exists():
        return []

    checkpoints: list[PipelineCheckpoint] = []
    for f in sorted(p_dir.glob("*.json")):
        try:
            with f.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            if isinstance(payload, dict) and "pipeline_id" in payload:
                checkpoints.append(PipelineCheckpoint.from_dict(payload))
        except Exception:
            continue

    # Sort descending by updated_at_utc or started_at_utc
    checkpoints.sort(key=lambda cp: cp.updated_at_utc, reverse=True)
    return checkpoints


def find_latest_checkpoint(
    case_dir: pathlib.Path, playbook_name: str | None = None
) -> PipelineCheckpoint | None:
    cps = list_checkpoints(case_dir)
    if playbook_name:
        cps = [cp for cp in cps if cp.playbook_name == playbook_name]
    return cps[0] if cps else None
