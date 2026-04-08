from __future__ import annotations

import dataclasses
import json
import pathlib
from collections.abc import Iterable, Sequence
from typing import Any

from lockknife.core._case_common import (
    _job_log_path,
    _json_safe_value,
    _utc_now,
    load_case_manifest,
    save_case_manifest,
)
from lockknife.core._case_models import CaseJob, CaseJobStep, CaseManifest


def _next_job_id(manifest: CaseManifest) -> str:
    return f"job-{len(manifest.jobs) + 1:04d}"


def _find_job_index(manifest: CaseManifest, job_id: str) -> int | None:
    for index, job in enumerate(manifest.jobs):
        if job.job_id == job_id:
            return index
    return None


def _job_step(step_id: str, label: str, status: str, *, message: str | None = None) -> CaseJobStep:
    now = _utc_now()
    return CaseJobStep(
        step_id=step_id,
        label=label,
        status=status,
        started_at_utc=now,
        ended_at_utc=None if status == "running" else now,
        message=message,
    )


def _replace_job_step_status(
    steps: Iterable[CaseJobStep],
    *,
    step_id: str,
    status: str,
    message: str | None = None,
) -> list[CaseJobStep]:
    now = _utc_now()
    updated_steps: list[CaseJobStep] = []
    for step in steps:
        if step.step_id != step_id:
            updated_steps.append(step)
            continue
        updated_steps.append(
            dataclasses.replace(
                step,
                status=status,
                ended_at_utc=None if status == "running" else now,
                message=message or step.message,
            )
        )
    return updated_steps


def _job_log_event(
    case_dir: pathlib.Path, job_id: str, *, level: str, message: str, step_id: str | None = None
) -> None:
    payload = {
        "timestamp_utc": _utc_now(),
        "level": level,
        "message": message,
    }
    if step_id:
        payload["step_id"] = step_id
    with _job_log_path(case_dir, job_id).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")


def _job_summary_payload(job: CaseJob) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "action_id": job.action_id,
        "action_label": job.action_label,
        "workflow_kind": job.workflow_kind,
        "status": job.status,
        "resumable": job.resumable,
        "device_serial": job.device_serial,
        "attempt_count": job.attempt_count,
        "latest_message": job.latest_message,
        "error_message": job.error_message,
        "recovery_hint": job.recovery_hint,
        "logs_path": job.logs_path,
        "result_artifact_ids": list(job.result_artifact_ids),
        "updated_at_utc": job.updated_at_utc,
        "started_at_utc": job.started_at_utc,
        "ended_at_utc": job.ended_at_utc,
    }


def _job_logs_tail(
    case_dir: pathlib.Path, job: CaseJob, *, limit: int = 20
) -> list[dict[str, Any]]:
    if not job.logs_path:
        return []
    path = pathlib.Path(job.logs_path)
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    tail: list[dict[str, Any]] = []
    for line in lines:
        try:
            tail.append(json.loads(line))
        except Exception:
            tail.append({"timestamp_utc": _utc_now(), "level": "info", "message": line})
    return tail


def _job_detail_payload(case_dir: pathlib.Path, job: CaseJob) -> dict[str, Any]:
    payload = _job_summary_payload(job)
    payload.update(
        {
            "params": _json_safe_value(job.params),
            "steps": [dataclasses.asdict(step) for step in job.steps],
            "logs_tail": _job_logs_tail(case_dir, job),
        }
    )
    return payload


def _workflow_kind_for_action(action_id: str) -> str:
    prefix, _, _rest = action_id.partition(".")
    return prefix or "workflow"


def _job_terminal(job: CaseJob) -> bool:
    return job.status in {"succeeded", "partial", "failed", "cancelled"}


def _job_resumable_status(job: CaseJob) -> bool:
    return job.resumable and job.status in {"failed", "partial", "cancelled"}


def _job_artifact_ids_from_payload(payload: Any) -> list[str]:
    found: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            artifact_id = value.get("artifact_id")
            if isinstance(artifact_id, str) and artifact_id.strip() and artifact_id not in found:
                found.append(artifact_id)
            nested_ids = value.get("artifact_ids")
            if isinstance(nested_ids, list):
                for item in nested_ids:
                    if isinstance(item, str) and item.strip() and item not in found:
                        found.append(item)
            for inner in value.values():
                visit(inner)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(payload)
    return found


def start_case_job(
    case_dir: pathlib.Path,
    *,
    action_id: str,
    action_label: str,
    params: dict[str, Any],
    device_serial: str | None = None,
    resumable: bool = True,
    existing_job_id: str | None = None,
) -> CaseJob:
    manifest = load_case_manifest(case_dir)
    now = _utc_now()
    clean_params = {
        str(key): _json_safe_value(value)
        for key, value in params.items()
        if value is not None and str(key) not in {"resume_job_id", "retry_job_id"}
    }
    if existing_job_id:
        job_index = _find_job_index(manifest, existing_job_id)
        if job_index is None:
            raise ValueError(f"Job {existing_job_id} not found")
        previous = manifest.jobs[job_index]
        attempt_count = previous.attempt_count + 1
        job_id = previous.job_id
        created_at = previous.created_at_utc
        steps = list(previous.steps)
        result_artifact_ids = list(previous.result_artifact_ids)
    else:
        job_index = None
        attempt_count = 1
        job_id = _next_job_id(manifest)
        created_at = now
        steps = []
        result_artifact_ids = []

    steps.append(
        _job_step(
            f"attempt-{attempt_count}-dispatch",
            "Dispatch workflow",
            "completed",
            message=action_label,
        )
    )
    steps.append(_job_step(f"attempt-{attempt_count}-execute", "Execute workflow", "running"))
    job = CaseJob(
        job_id=job_id,
        action_id=action_id,
        action_label=action_label,
        workflow_kind=_workflow_kind_for_action(action_id),
        status="running",
        resumable=resumable,
        created_at_utc=created_at,
        updated_at_utc=now,
        started_at_utc=now,
        ended_at_utc=None,
        device_serial=device_serial,
        attempt_count=attempt_count,
        params=clean_params,
        latest_message=None,
        error_message=None,
        recovery_hint=None,
        logs_path=str(_job_log_path(case_dir, job_id)),
        result_artifact_ids=result_artifact_ids,
        steps=steps,
    )
    if job_index is None:
        manifest.jobs.append(job)
    else:
        manifest.jobs[job_index] = job
    manifest.updated_at_utc = now
    save_case_manifest(case_dir, manifest)
    _job_log_event(
        case_dir,
        job.job_id,
        level="info",
        message=f"Started {action_id} attempt {attempt_count}",
        step_id=f"attempt-{attempt_count}-execute",
    )
    return job


def complete_case_job(
    case_dir: pathlib.Path,
    *,
    job_id: str,
    message: str | None = None,
    payload: Any = None,
    recovery_hint: str | None = None,
    status: str = "succeeded",
) -> CaseJob:
    manifest = load_case_manifest(case_dir)
    job_index = _find_job_index(manifest, job_id)
    if job_index is None:
        raise ValueError(f"Job {job_id} not found")
    existing = manifest.jobs[job_index]
    attempt = existing.attempt_count
    steps = _replace_job_step_status(
        existing.steps,
        step_id=f"attempt-{attempt}-execute",
        status="completed" if status != "failed" else "failed",
        message=message,
    )
    steps.append(
        _job_step(f"attempt-{attempt}-finalize", "Persist results", "completed", message=message)
    )
    now = _utc_now()
    job = dataclasses.replace(
        existing,
        status=status,
        updated_at_utc=now,
        ended_at_utc=now,
        latest_message=message,
        error_message=None if status != "failed" else existing.error_message,
        recovery_hint=recovery_hint,
        result_artifact_ids=_job_artifact_ids_from_payload(payload)
        or list(existing.result_artifact_ids),
        steps=steps,
    )
    manifest.jobs[job_index] = job
    manifest.updated_at_utc = now
    save_case_manifest(case_dir, manifest)
    _job_log_event(
        case_dir, job_id, level="info", message=message or f"{existing.action_label} completed"
    )
    return job


def fail_case_job(
    case_dir: pathlib.Path,
    *,
    job_id: str,
    error_message: str,
    recovery_hint: str | None = None,
) -> CaseJob:
    manifest = load_case_manifest(case_dir)
    job_index = _find_job_index(manifest, job_id)
    if job_index is None:
        raise ValueError(f"Job {job_id} not found")
    existing = manifest.jobs[job_index]
    attempt = existing.attempt_count
    steps = _replace_job_step_status(
        existing.steps,
        step_id=f"attempt-{attempt}-execute",
        status="failed",
        message=error_message,
    )
    steps.append(
        _job_step(
            f"attempt-{attempt}-finalize",
            "Persist failure",
            "completed",
            message=recovery_hint or error_message,
        )
    )
    now = _utc_now()
    job = dataclasses.replace(
        existing,
        status="failed",
        updated_at_utc=now,
        ended_at_utc=now,
        latest_message=None,
        error_message=error_message,
        recovery_hint=recovery_hint,
        steps=steps,
    )
    manifest.jobs[job_index] = job
    manifest.updated_at_utc = now
    save_case_manifest(case_dir, manifest)
    _job_log_event(case_dir, job_id, level="error", message=error_message)
    if recovery_hint:
        _job_log_event(case_dir, job_id, level="warn", message=recovery_hint)
    return job


def query_case_jobs(
    case_dir: pathlib.Path,
    *,
    statuses: Sequence[str] | None = None,
    workflow_kinds: Sequence[str] | None = None,
    action_ids: Sequence[str] | None = None,
    query: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    manifest = load_case_manifest(case_dir)
    status_set = {item for item in (statuses or []) if item}
    workflow_set = {item for item in (workflow_kinds or []) if item}
    action_set = {item for item in (action_ids or []) if item}
    needle = (query or "").strip().lower()

    jobs = list(manifest.jobs)
    if status_set:
        jobs = [job for job in jobs if job.status in status_set]
    if workflow_set:
        jobs = [job for job in jobs if job.workflow_kind in workflow_set]
    if action_set:
        jobs = [job for job in jobs if job.action_id in action_set]
    if needle:
        jobs = [
            job
            for job in jobs
            if needle in job.job_id.lower()
            or needle in job.action_id.lower()
            or needle in job.action_label.lower()
            or needle in (job.latest_message or "").lower()
            or needle in (job.error_message or "").lower()
            or needle in (job.recovery_hint or "").lower()
        ]
    jobs.sort(key=lambda item: item.updated_at_utc, reverse=True)
    if limit is not None and limit > 0:
        jobs = jobs[:limit]

    return {
        "case_dir": str(case_dir),
        "case_id": manifest.case_id,
        "title": manifest.title,
        "job_count": len(jobs),
        "total_job_count": len(manifest.jobs),
        "filters": {
            "statuses": list(statuses or []),
            "workflow_kinds": list(workflow_kinds or []),
            "action_ids": list(action_ids or []),
            "query": query or "",
            "limit": limit,
        },
        "jobs": [_job_summary_payload(job) for job in jobs],
    }


def case_job_details(case_dir: pathlib.Path, *, job_id: str) -> dict[str, Any] | None:
    manifest = load_case_manifest(case_dir)
    job_index = _find_job_index(manifest, job_id)
    if job_index is None:
        return None
    return {
        "case_dir": str(case_dir),
        "case_id": manifest.case_id,
        "job": _job_detail_payload(case_dir, manifest.jobs[job_index]),
    }


def case_job_rerun_context(
    case_dir: pathlib.Path, *, job_id: str, mode: str
) -> dict[str, Any] | None:
    manifest = load_case_manifest(case_dir)
    job_index = _find_job_index(manifest, job_id)
    if job_index is None:
        return None
    job = manifest.jobs[job_index]
    if mode == "resume" and not _job_resumable_status(job):
        raise ValueError(f"Job {job_id} is not resumable")
    if mode == "retry" and not _job_terminal(job):
        raise ValueError(f"Job {job_id} must finish before it can be retried")
    return {
        "case_dir": str(case_dir),
        "case_id": manifest.case_id,
        "mode": mode,
        "action_id": job.action_id,
        "action_label": job.action_label,
        "params": _json_safe_value(job.params),
        "job": _job_summary_payload(job),
    }
