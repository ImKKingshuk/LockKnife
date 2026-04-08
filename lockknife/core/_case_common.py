from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import pathlib
from typing import Any

from lockknife.core._case_models import (
    CaseArtifact,
    CaseJob,
    CaseJobStep,
    CaseManifest,
    CaseRuntimeScript,
    CaseRuntimeSession,
)
from lockknife.core.path_safety import validate_relative_component
from lockknife.core.serialize import write_json


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _sha256_file(path: pathlib.Path) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def _manifest_path(case_dir: pathlib.Path) -> pathlib.Path:
    return case_dir / "case_manifest.json"


def _job_log_path(case_dir: pathlib.Path, job_id: str) -> pathlib.Path:
    path = case_dir / "logs" / "jobs" / f"{job_id}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _runtime_session_log_path(case_dir: pathlib.Path, session_id: str) -> pathlib.Path:
    path = case_dir / "logs" / "runtime" / f"{session_id}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _runtime_session_summary_path(case_dir: pathlib.Path, session_id: str) -> pathlib.Path:
    path = case_dir / "derived" / "runtime" / f"{session_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def case_output_path(case_dir: pathlib.Path, *, area: str, filename: str) -> pathlib.Path:
    safe_area = validate_relative_component(area, label="case output area")
    safe_filename = validate_relative_component(filename, label="case output filename")
    path = case_dir / safe_area / safe_filename
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _normalize_case_path(case_dir: pathlib.Path, path: str | pathlib.Path) -> str:
    raw_path = pathlib.Path(path)
    resolved = raw_path.resolve() if raw_path.is_absolute() else (case_dir / raw_path).resolve()
    try:
        return str(resolved.relative_to(case_dir.resolve()))
    except ValueError:
        return str(resolved)


def create_case_workspace(
    *,
    case_dir: pathlib.Path,
    case_id: str,
    examiner: str,
    title: str,
    notes: str | None = None,
    target_serials: list[str] | None = None,
) -> pathlib.Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    for name in ("evidence", "derived", "reports", "logs", "exports", "tmp"):
        (case_dir / name).mkdir(exist_ok=True)
    (case_dir / "logs" / "jobs").mkdir(parents=True, exist_ok=True)
    (case_dir / "logs" / "runtime").mkdir(parents=True, exist_ok=True)
    (case_dir / "derived" / "runtime").mkdir(parents=True, exist_ok=True)

    now = _utc_now()
    manifest = CaseManifest(
        schema_version=4,
        case_id=case_id,
        title=title,
        examiner=examiner,
        notes=notes,
        created_at_utc=now,
        updated_at_utc=now,
        workspace_root=str(case_dir.resolve()),
        target_serials=list(target_serials or []),
        artifacts=[],
        jobs=[],
        runtime_sessions=[],
    )
    save_case_manifest(case_dir, manifest)
    return case_dir


def load_case_manifest(case_dir: pathlib.Path) -> CaseManifest:
    raw = json.loads(_manifest_path(case_dir).read_text(encoding="utf-8"))
    artifacts = [CaseArtifact(**item) for item in raw.pop("artifacts", [])]
    jobs = []
    for item in raw.pop("jobs", []):
        steps = [CaseJobStep(**step) for step in item.pop("steps", [])]
        jobs.append(CaseJob(steps=steps, **item))
    runtime_sessions = []
    for item in raw.pop("runtime_sessions", []):
        script_inventory = [
            CaseRuntimeScript(**script) for script in item.pop("script_inventory", [])
        ]
        runtime_sessions.append(CaseRuntimeSession(script_inventory=script_inventory, **item))
    raw.setdefault("schema_version", 2)
    return CaseManifest(artifacts=artifacts, jobs=jobs, runtime_sessions=runtime_sessions, **raw)


def save_case_manifest(case_dir: pathlib.Path, manifest: CaseManifest) -> pathlib.Path:
    path = _manifest_path(case_dir)
    write_json(path, dataclasses.asdict(manifest))
    return path


def _json_safe_value(value: Any) -> Any:
    if isinstance(value, pathlib.Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe_value(inner) for key, inner in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe_value(item) for item in value]
    return value
