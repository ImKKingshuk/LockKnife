from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

from lockknife.core.case import (
    case_chain_of_custody_items,
    case_output_path,
    complete_case_job,
    fail_case_job,
    find_case_artifact,
    load_case_manifest,
    register_case_artifact,
    start_case_job,
)
from lockknife.core.device import DeviceManager
from lockknife.core.path_safety import validate_user_path_text
from lockknife.modules.reporting.chain_of_custody import EvidenceItem

@dataclasses.dataclass
class _CaseJobTracker:
    case_dir: pathlib.Path
    action_id: str
    job_id: str
    finalized: bool = False


_JOB_TRACKER_STACK: list[_CaseJobTracker] = []
_JOB_MANAGED_ACTION_PREFIXES = (
    "ai.",
    "extraction.",
    "forensics.",
    "intelligence.",
    "network.",
    "runtime.",
    "security.",
)

def _asdict(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, (list, tuple)):
        return [_asdict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _asdict(v) for k, v in obj.items()}
    if isinstance(obj, pathlib.Path):
        return str(obj)
    return obj

def _current_job_tracker() -> _CaseJobTracker | None:
    return _JOB_TRACKER_STACK[-1] if _JOB_TRACKER_STACK else None


def _job_action_label(action_id: str) -> str:
    return action_id.replace(".", " ").replace("_", " ").title()

def _should_track_case_job(action_id: str, params: dict[str, Any]) -> bool:
    return _path_param(params.get("case_dir")) is not None and (
        action_id.startswith(_JOB_MANAGED_ACTION_PREFIXES) or action_id == "case.enrich"
    )

def _job_device_serial(params: dict[str, Any]) -> str | None:
    return _opt(params.get("device_serial")) or _opt(params.get("serial")) or _opt(params.get("device_id"))

def _maybe_start_case_job(action_id: str, params: dict[str, Any]) -> _CaseJobTracker | None:
    if not _should_track_case_job(action_id, params):
        return None
    case_dir = _path_param(params.get("case_dir"))
    if case_dir is None or not (case_dir / "case_manifest.json").exists():
        return None
    from lockknife.core.case import start_case_job

    job = start_case_job(
        case_dir,
        action_id=action_id,
        action_label=_job_action_label(action_id),
        params=params,
        device_serial=_job_device_serial(params),
        existing_job_id=_opt(params.get("resume_job_id")) or _opt(params.get("retry_job_id")),
    )
    return _CaseJobTracker(case_dir=case_dir, action_id=action_id, job_id=job.job_id)

def _payload_has_partial_signal(payload: Any) -> bool:
    if isinstance(payload, dict):
        for key in ("missing_parent_ids", "warnings", "errors"):
            value = payload.get(key)
            if isinstance(value, list) and value:
                return True
        for key in ("failed", "failed_count", "failure_count", "skipped", "skipped_count"):
            value = payload.get(key)
            if isinstance(value, int) and value > 0:
                return True
        for key in ("ok", "configured", "installed"):
            if payload.get(key) is False:
                return True
        return any(_payload_has_partial_signal(value) for value in payload.values())
    if isinstance(payload, list):
        return any(_payload_has_partial_signal(item) for item in payload)
    return False

def _job_recovery_hint(action_id: str, message: str | None = None) -> str | None:
    if action_id.startswith("runtime."):
        return "Check device connectivity, target package/process values, and Frida/server availability before retrying."
    if action_id.startswith(("extraction.", "forensics.")):
        return "Verify the device is unlocked, accessible, and that the case workspace has enough space, then retry."
    if action_id.startswith(("intelligence.", "ai.")):
        return "Verify source artifacts, network access, and any API credentials before retrying."
    if action_id.startswith(("network.", "security.")):
        return "Verify required inputs, tools, and permissions before retrying."
    if message and "Unsupported action" in message:
        return "Choose a supported workflow or refresh the TUI action catalog."
    return None

def _job_json_payload(job: Any, *, case_dir: pathlib.Path | None = None) -> dict[str, Any]:
    payload = {
        "job_id": getattr(job, "job_id", None),
        "action_id": getattr(job, "action_id", None),
        "action_label": getattr(job, "action_label", None),
        "workflow_kind": getattr(job, "workflow_kind", None),
        "status": getattr(job, "status", None),
        "resumable": getattr(job, "resumable", None),
        "device_serial": getattr(job, "device_serial", None),
        "attempt_count": getattr(job, "attempt_count", None),
        "latest_message": getattr(job, "latest_message", None),
        "error_message": getattr(job, "error_message", None),
        "recovery_hint": getattr(job, "recovery_hint", None),
        "logs_path": getattr(job, "logs_path", None),
        "result_artifact_ids": list(getattr(job, "result_artifact_ids", []) or []),
        "updated_at_utc": getattr(job, "updated_at_utc", None),
        "started_at_utc": getattr(job, "started_at_utc", None),
        "ended_at_utc": getattr(job, "ended_at_utc", None),
    }
    if case_dir is not None:
        payload["case_dir"] = str(case_dir)
    return payload

def _ok(payload: Any, message: str) -> dict[str, Any]:
    payload_data = _asdict(payload)
    result: dict[str, Any] = {
        "ok": True,
        "message": message,
        "data_json": json.dumps(payload_data, default=str),
        "logs": [{"level": "info", "message": message}],
    }
    tracker = _current_job_tracker()
    if tracker is not None and not tracker.finalized:
        status = "partial" if _payload_has_partial_signal(payload_data) else "succeeded"
        recovery_hint = _job_recovery_hint(tracker.action_id, message) if status == "partial" else None
        from lockknife.core.case import complete_case_job

        job = complete_case_job(
            tracker.case_dir,
            job_id=tracker.job_id,
            message=message,
            payload=payload_data,
            recovery_hint=recovery_hint,
            status=status,
        )
        tracker.finalized = True
        result["job_json"] = json.dumps(_job_json_payload(job, case_dir=tracker.case_dir), default=str)
        if recovery_hint:
            result["logs"].append({"level": "warn", "message": recovery_hint})
    return result

def _err(message: str) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": False, "error": message, "logs": [{"level": "error", "message": message}]}
    tracker = _current_job_tracker()
    if tracker is not None and not tracker.finalized:
        recovery_hint = _job_recovery_hint(tracker.action_id, message)
        from lockknife.core.case import fail_case_job

        job = fail_case_job(tracker.case_dir, job_id=tracker.job_id, error_message=message, recovery_hint=recovery_hint)
        tracker.finalized = True
        result["job_json"] = json.dumps(_job_json_payload(job, case_dir=tracker.case_dir), default=str)
        result["data_json"] = json.dumps(
            {"case_dir": str(tracker.case_dir), "job": _job_json_payload(job, case_dir=tracker.case_dir)},
            default=str,
        )
        if recovery_hint:
            result["logs"].append({"level": "warn", "message": recovery_hint})
    return result

def _require(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if value is None or str(value).strip() == "":
        raise ValueError(f"Missing required parameter: {key}")
    return str(value)

def _opt(value: Any) -> str | None:
    if value is None:
        return None
    v = str(value).strip()
    return v if v else None

def _path_param(value: Any) -> pathlib.Path | None:
    raw = _opt(value)
    if raw is None:
        return None
    return pathlib.Path(validate_user_path_text(raw, label="path"))

def _csv_list(value: Any) -> list[str]:
    raw = _opt(value)
    if raw is None:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]

def _int_param(value: Any) -> int | None:
    raw = _opt(value)
    if raw is None:
        return None
    return int(raw)

def _bool_param(value: Any) -> bool:
    raw = _opt(value)
    if raw is None:
        return False
    return raw.lower() in {"1", "true", "yes", "on"}

def _json_dict_param(value: Any) -> dict[str, Any]:
    raw = _opt(value)
    if raw is None:
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("metadata_json must decode to an object")
    return parsed

def _resolve_case_output(
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
    *,
    area: str,
    filename: str,
) -> tuple[pathlib.Path | None, bool]:
    if output is not None:
        return output, False
    if case_dir is None:
        return None, False
    return case_output_path(case_dir, area=area, filename=filename), True

def _register_case_output(
    case_dir: pathlib.Path | None,
    *,
    path: pathlib.Path,
    category: str,
    source_command: str,
    device_serial: str | None = None,
    input_paths: list[str] | None = None,
    parent_artifact_ids: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> str | None:
    if case_dir is None:
        return None
    artifact = register_case_artifact(
        case_dir=case_dir,
        path=path,
        category=category,
        source_command=source_command,
        device_serial=device_serial,
        input_paths=input_paths,
        parent_artifact_ids=parent_artifact_ids,
        metadata=metadata,
    )
    return getattr(artifact, "artifact_id", None)

def _safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)
    return cleaned.strip("_") or "item"

def _require_runtime_case_dir(params: dict[str, Any]) -> pathlib.Path:
    case_dir = _path_param(params.get("case_dir"))
    if case_dir is None:
        raise ValueError("Case directory is required for managed runtime sessions")
    return case_dir

def _runtime_session_name(params: dict[str, Any], *, default: str) -> str:
    return _opt(params.get("session_name")) or default

def _case_filter_kwargs(params: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "categories": _csv_list(params.get("categories")),
        "exclude_categories": _csv_list(params.get("exclude_categories")),
        "source_commands": _csv_list(params.get("source_commands")),
        "device_serials": _csv_list(params.get("device_serials")),
    }

def _case_job_filter_kwargs(params: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "statuses": _csv_list(params.get("statuses")),
        "workflow_kinds": _csv_list(params.get("workflow_kinds")),
        "action_ids": _csv_list(params.get("action_ids")),
    }

def _artifact_ref_from_params(params: dict[str, Any]) -> dict[str, Any]:
    artifact_id = _opt(params.get("artifact_id"))
    artifact_path = _opt(params.get("path"))
    if artifact_id:
        return {"artifact_id": artifact_id, "path": None}
    if artifact_path:
        return {"artifact_id": None, "path": pathlib.Path(artifact_path)}
    raise ValueError("Provide artifact_id or path")

def _template_path(template: str) -> pathlib.Path:
    template_l = template.lower()
    if template_l == "executive":
        name = "executive_report.html"
    elif template_l == "chain_of_custody":
        name = "chain_of_custody.html"
    else:
        name = "technical_report.html"
    return pathlib.Path(__file__).resolve().parents[1] / "lockknife" / "templates" / name

def _resolve_report_case_id(params: dict[str, Any], case_dir: pathlib.Path | None) -> str:
    if _opt(params.get("case_id")):
        return _require(params, "case_id")
    if case_dir is not None:
        return str(load_case_manifest(case_dir).case_id)
    raise ValueError("case_id is required when case_dir is not provided")

def _resolve_report_examiner(params: dict[str, Any], case_dir: pathlib.Path | None) -> str:
    if _opt(params.get("examiner")):
        return _require(params, "examiner")
    if case_dir is not None:
        return str(load_case_manifest(case_dir).examiner)
    raise ValueError("examiner is required when case_dir is not provided")

def _report_rows(artifacts: Any, context: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(artifacts, list) and all(isinstance(row, dict) for row in artifacts):
        return artifacts
    evidence_inventory = context.get("evidence_inventory")
    if isinstance(evidence_inventory, list) and evidence_inventory:
        return [row for row in evidence_inventory if isinstance(row, dict)]
    if isinstance(artifacts, dict):
        return [artifacts]
    return [{"artifact": "data", "value": json.dumps(artifacts)}]

def _custody_evidence_items(case_dir: pathlib.Path | None, evidence_paths: list[str]) -> list[EvidenceItem]:
    if case_dir is None:
        return [EvidenceItem(name=pathlib.Path(path).name, path=path) for path in evidence_paths]
    items: list[EvidenceItem] = []
    for path in evidence_paths:
        artifact = find_case_artifact(case_dir, path=path)
        if artifact is not None:
            items.extend(case_chain_of_custody_items(case_dir, artifacts=[artifact]))
        else:
            items.append(EvidenceItem(name=pathlib.Path(path).name, path=path))
    return items

def _render_integrity_text(report: dict[str, Any]) -> str:
    summary = report["summary"]
    custody_chain_obj = report.get("custody_chain")
    custody_chain: dict[str, Any] = custody_chain_obj if isinstance(custody_chain_obj, dict) else {}
    verification_obj = custody_chain.get("verification")
    verification: dict[str, Any] = verification_obj if isinstance(verification_obj, dict) else {}
    lines = [
        f"Case integrity report: {report['case_id']}",
        f"Examiner: {report['examiner']}",
        f"Verified at: {report['verified_at_utc']}",
        "",
        "Summary:",
        f"- Artifacts: {summary['artifact_count']}",
        f"- Verified: {summary['verified_count']}",
        f"- Modified: {summary['modified_count']}",
        f"- Missing: {summary['missing_count']}",
        f"- Unreadable: {summary['unreadable_count']}",
        f"- Unsupported: {summary['unsupported_count']}",
        f"- Custody chain: {summary.get('custody_chain_status', 'unknown')}",
        "",
        "Custody chain:",
        f"- Entries: {custody_chain.get('entry_count', 0)}",
        f"- Chain head: {custody_chain.get('chain_head_sha256') or 'n/a'}",
        f"- Verification: {verification.get('status', 'unknown')}",
        "",
        f"Advisory: {report['advisory']}",
        "",
    ]
    return "\n".join(lines)

def _json_from_param(value: Any) -> Any:
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return {}
    return value

def _load_config_text(devices: DeviceManager) -> tuple[str, str | None]:
    try:
        from lockknife.core.config import load_config

        loaded = load_config()
        path = str(loaded.path) if loaded.path else None
    except Exception:
        path = None
    if path and pathlib.Path(path).exists():
        return pathlib.Path(path).read_text(encoding="utf-8"), path
    return "", None
