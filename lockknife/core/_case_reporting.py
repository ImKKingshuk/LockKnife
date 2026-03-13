from __future__ import annotations



import json

import pathlib

import zipfile

from collections import Counter, defaultdict

from typing import Any, Sequence



from lockknife.modules.reporting.chain_of_custody import (
    EvidenceItem,
    build_chain_of_custody_payload,
    generate_chain_of_custody,
)



from lockknife.core._case_artifacts import _artifact_filter_payload, _select_case_artifacts

from lockknife.core._case_common import (
    _manifest_path,
    _normalize_case_path,
    _sha256_file,
    _utc_now,
    load_case_manifest,
)

from lockknife.core._case_jobs import _job_resumable_status, _job_summary_payload

from lockknife.core._case_models import CaseArtifact

from lockknife.core._case_runtime import _runtime_session_summary_payload



def summarize_case_manifest(
    case_dir: pathlib.Path,
    *,
    categories: list[str] | tuple[str, ...] | None = None,
    exclude_categories: list[str] | tuple[str, ...] | None = None,
    source_commands: list[str] | tuple[str, ...] | None = None,
    device_serials: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    manifest = load_case_manifest(case_dir)
    artifacts = _select_case_artifacts(
        manifest,
        categories=categories,
        exclude_categories=exclude_categories,
        source_commands=source_commands,
        device_serials=device_serials,
    )
    artifact_ids = {artifact.artifact_id for artifact in artifacts}
    category_counts = Counter(artifact.category for artifact in artifacts)
    command_counts = Counter(artifact.source_command for artifact in artifacts)
    device_counts = Counter(artifact.device_serial or "unknown" for artifact in artifacts)
    linked_artifacts = sum(1 for artifact in artifacts if any(parent_id in artifact_ids for parent_id in artifact.parent_artifact_ids))
    root_artifacts = len(artifacts) - linked_artifacts
    external_inputs = sum(1 for artifact in artifacts if artifact.input_paths and not any(parent_id in artifact_ids for parent_id in artifact.parent_artifact_ids))
    parent_edges = sum(sum(1 for parent_id in artifact.parent_artifact_ids if parent_id in artifact_ids) for artifact in artifacts)

    def _rows(counter: Counter[str]) -> list[dict[str, Any]]:
        return [{"name": name, "count": count} for name, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))]

    jobs_by_status = Counter(job.status for job in manifest.jobs)
    jobs_by_workflow = Counter(job.workflow_kind for job in manifest.jobs)
    recent_jobs = sorted(manifest.jobs, key=lambda item: item.updated_at_utc, reverse=True)[:5]
    runtime_by_status = Counter(session.status for session in manifest.runtime_sessions)
    runtime_by_kind = Counter(session.session_kind for session in manifest.runtime_sessions)
    recent_runtime_sessions = sorted(
        manifest.runtime_sessions,
        key=lambda item: item.updated_at_utc,
        reverse=True,
    )[:5]

    return {
        "case_dir": str(case_dir),
        "case_id": manifest.case_id,
        "title": manifest.title,
        "examiner": manifest.examiner,
        "schema_version": manifest.schema_version,
        "workspace_root": manifest.workspace_root,
        "target_serials": manifest.target_serials,
        "artifact_count": len(artifacts),
        "total_artifact_count": len(manifest.artifacts),
        "artifacts_by_category": _rows(category_counts),
        "artifacts_by_source_command": _rows(command_counts),
        "artifacts_by_device_serial": _rows(device_counts),
        "filters": _artifact_filter_payload(
            categories=categories,
            exclude_categories=exclude_categories,
            source_commands=source_commands,
            device_serials=device_serials,
        ),
        "lineage": {
            "root_artifacts": root_artifacts,
            "linked_artifacts": linked_artifacts,
            "parent_edges": parent_edges,
            "artifacts_with_external_inputs": external_inputs,
        },
        "jobs": {
            "total": len(manifest.jobs),
            "running": jobs_by_status.get("running", 0),
            "succeeded": jobs_by_status.get("succeeded", 0),
            "partial": jobs_by_status.get("partial", 0),
            "failed": jobs_by_status.get("failed", 0),
            "cancelled": jobs_by_status.get("cancelled", 0),
            "resumable": sum(1 for job in manifest.jobs if _job_resumable_status(job)),
            "by_workflow": _rows(jobs_by_workflow),
        },
        "recent_jobs": [_job_summary_payload(job) for job in recent_jobs],
        "runtime_sessions": {
            "total": len(manifest.runtime_sessions),
            "active": runtime_by_status.get("active", 0),
            "reconnecting": runtime_by_status.get("reconnecting", 0),
            "stopped": runtime_by_status.get("stopped", 0),
            "failed": runtime_by_status.get("failed", 0),
            "by_kind": _rows(runtime_by_kind),
        },
        "recent_runtime_sessions": [
            _runtime_session_summary_payload(session) for session in recent_runtime_sessions
        ],
    }

def _resolve_case_artifact_path(case_dir: pathlib.Path, artifact: CaseArtifact) -> pathlib.Path:
    path = pathlib.Path(artifact.path)
    return path if path.is_absolute() else (case_dir / artifact.path)

def case_evidence_inventory(
    case_dir: pathlib.Path,
    *,
    artifacts: Sequence[CaseArtifact] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for artifact in list(artifacts or load_case_manifest(case_dir).artifacts):
        artifact_path = _resolve_case_artifact_path(case_dir, artifact)
        exists = artifact_path.exists()
        current_sha256: str | None = None
        current_size_bytes: int | None = None
        status = "missing"

        if exists and artifact_path.is_file():
            try:
                current_sha256, current_size_bytes = _sha256_file(artifact_path)
                status = "verified" if artifact.sha256 == current_sha256 else "modified"
            except OSError:
                status = "unreadable"
        elif exists:
            status = "unsupported"

        rows.append(
            {
                "artifact_id": artifact.artifact_id,
                "path": artifact.path,
                "absolute_path": str(artifact_path.resolve()) if exists else str(artifact_path),
                "category": artifact.category,
                "source_command": artifact.source_command,
                "device_serial": artifact.device_serial,
                "created_at_utc": artifact.created_at_utc,
                "recorded_sha256": artifact.sha256,
                "current_sha256": current_sha256,
                "recorded_size_bytes": artifact.size_bytes,
                "current_size_bytes": current_size_bytes,
                "exists": exists,
                "status": status,
                "input_paths": list(artifact.input_paths),
                "parent_artifact_ids": list(artifact.parent_artifact_ids),
                "metadata": artifact.metadata,
            }
        )

    return rows

def case_integrity_report(
    case_dir: pathlib.Path,
    *,
    artifacts: Sequence[CaseArtifact] | None = None,
) -> dict[str, Any]:
    manifest = load_case_manifest(case_dir)
    selected_artifacts = list(artifacts or manifest.artifacts)
    inventory = case_evidence_inventory(case_dir, artifacts=selected_artifacts)
    status_counts = Counter(row["status"] for row in inventory)
    category_counts = Counter(row["category"] for row in inventory)
    custody_chain = build_chain_of_custody_payload(
        case_id=manifest.case_id,
        examiner=manifest.examiner,
        notes=None,
        evidence=case_chain_of_custody_items(case_dir, artifacts=selected_artifacts),
    )

    summary: dict[str, Any] = {
        "artifact_count": len(inventory),
        "verified_count": status_counts.get("verified", 0),
        "modified_count": status_counts.get("modified", 0),
        "missing_count": status_counts.get("missing", 0),
        "unreadable_count": status_counts.get("unreadable", 0),
        "unsupported_count": status_counts.get("unsupported", 0),
        "category_counts": dict(sorted(category_counts.items())),
        "custody_chain_status": str((custody_chain.get("verification") or {}).get("status") or "unknown"),
    }
    if summary["modified_count"] > 0:
        advisory = "Integrity verification detected modified artifacts; preserve originals and investigate drift before relying on derived conclusions."
    elif summary["missing_count"] > 0:
        advisory = "Integrity verification detected missing artifacts; the case workspace is incomplete and downstream reporting should be reviewed carefully."
    else:
        advisory = "Integrity verification completed without detected artifact drift across the selected case inventory."

    return {
        "case_dir": str(case_dir),
        "case_id": manifest.case_id,
        "title": manifest.title,
        "examiner": manifest.examiner,
        "verified_at_utc": _utc_now(),
        "summary": summary,
        "custody_chain": {
            "entry_count": custody_chain.get("entry_count", 0),
            "chain_head_sha256": custody_chain.get("chain_head_sha256"),
            "verification": custody_chain.get("verification") or {},
        },
        "artifacts": inventory,
        "advisory": advisory,
    }

def case_chain_of_custody_items(
    case_dir: pathlib.Path,
    *,
    artifacts: Sequence[CaseArtifact] | None = None,
) -> list[EvidenceItem]:
    selected_artifacts = list(artifacts or load_case_manifest(case_dir).artifacts)
    inventory = case_evidence_inventory(case_dir, artifacts=selected_artifacts)
    inventory_by_id = {row["artifact_id"]: row for row in inventory}

    return [
        EvidenceItem(
            name=f"{artifact.artifact_id} · {pathlib.Path(artifact.path).name}",
            path=str(_resolve_case_artifact_path(case_dir, artifact)),
            sha256=artifact.sha256 or inventory_by_id.get(artifact.artifact_id, {}).get("current_sha256"),
            category=artifact.category,
            source_command=artifact.source_command,
            device_serial=artifact.device_serial,
            collected_at_utc=artifact.created_at_utc,
            size_bytes=artifact.size_bytes,
            integrity_status=inventory_by_id.get(artifact.artifact_id, {}).get("status"),
            metadata={
                "artifact_id": artifact.artifact_id,
                "parent_artifact_ids": list(artifact.parent_artifact_ids),
                "input_paths": list(artifact.input_paths),
            },
        )
        for artifact in selected_artifacts
    ]


def case_chain_of_custody_report(
    case_dir: pathlib.Path,
    *,
    notes: str | None = None,
    artifacts: Sequence[CaseArtifact] | None = None,
) -> dict[str, Any]:
    manifest = load_case_manifest(case_dir)
    return build_chain_of_custody_payload(
        case_id=manifest.case_id,
        examiner=manifest.examiner,
        notes=notes,
        evidence=case_chain_of_custody_items(case_dir, artifacts=artifacts),
    )

def generate_case_chain_of_custody(
    case_dir: pathlib.Path,
    *,
    notes: str | None = None,
    artifacts: Sequence[CaseArtifact] | None = None,
) -> str:
    manifest = load_case_manifest(case_dir)
    return generate_chain_of_custody(
        case_id=manifest.case_id,
        examiner=manifest.examiner,
        notes=notes,
        evidence=case_chain_of_custody_items(case_dir, artifacts=artifacts),
    )

def case_lineage_graph(
    case_dir: pathlib.Path,
    *,
    categories: list[str] | tuple[str, ...] | None = None,
    exclude_categories: list[str] | tuple[str, ...] | None = None,
    source_commands: list[str] | tuple[str, ...] | None = None,
    device_serials: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    manifest = load_case_manifest(case_dir)
    artifacts = _select_case_artifacts(
        manifest,
        categories=categories,
        exclude_categories=exclude_categories,
        source_commands=source_commands,
        device_serials=device_serials,
    )
    artifact_map = {artifact.artifact_id: artifact for artifact in artifacts}
    children_by_parent: dict[str, list[str]] = defaultdict(list)
    edges: list[dict[str, str]] = []

    for artifact in artifacts:
        for parent_id in artifact.parent_artifact_ids:
            if parent_id in artifact_map:
                children_by_parent[parent_id].append(artifact.artifact_id)
                edges.append({"parent_artifact_id": parent_id, "child_artifact_id": artifact.artifact_id})

    nodes = [
        {
            "artifact_id": artifact.artifact_id,
            "path": artifact.path,
            "category": artifact.category,
            "source_command": artifact.source_command,
            "device_serial": artifact.device_serial,
            "input_paths": artifact.input_paths,
            "parent_artifact_ids": artifact.parent_artifact_ids,
            "child_artifact_ids": children_by_parent.get(artifact.artifact_id, []),
        }
        for artifact in artifacts
    ]

    roots = [
        artifact.artifact_id
        for artifact in artifacts
        if not artifact.parent_artifact_ids or all(parent_id not in artifact_map for parent_id in artifact.parent_artifact_ids)
    ]

    return {
        "case_dir": str(case_dir),
        "case_id": manifest.case_id,
        "title": manifest.title,
        "examiner": manifest.examiner,
        "artifact_count": len(artifacts),
        "total_artifact_count": len(manifest.artifacts),
        "filters": _artifact_filter_payload(
            categories=categories,
            exclude_categories=exclude_categories,
            source_commands=source_commands,
            device_serials=device_serials,
        ),
        "root_artifact_ids": roots,
        "nodes": nodes,
        "edges": edges,
    }

def _add_path_to_zip(
    archive: zipfile.ZipFile,
    *,
    source_path: pathlib.Path,
    bundle_root: str,
    case_dir: pathlib.Path,
    written_arc_names: set[str],
    included_paths: set[str],
) -> None:
    if not source_path.exists():
        return
    if source_path.is_dir():
        for child in sorted(source_path.rglob("*")):
            if child.is_file():
                _add_path_to_zip(
                    archive,
                    source_path=child,
                    bundle_root=bundle_root,
                    case_dir=case_dir,
                    written_arc_names=written_arc_names,
                    included_paths=included_paths,
                )
        return

    normalized = _normalize_case_path(case_dir, source_path)
    arcname = f"{bundle_root}/{normalized}"
    if arcname in written_arc_names:
        included_paths.add(normalized)
        return
    archive.write(source_path, arcname=arcname)
    written_arc_names.add(arcname)
    included_paths.add(normalized)

def export_case_bundle(
    *,
    case_dir: pathlib.Path,
    output_path: pathlib.Path,
    include_registered_artifacts: bool = False,
    categories: list[str] | tuple[str, ...] | None = None,
    exclude_categories: list[str] | tuple[str, ...] | None = None,
    source_commands: list[str] | tuple[str, ...] | None = None,
    device_serials: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    manifest = load_case_manifest(case_dir)
    bundle_root = manifest.case_id
    selected_artifacts = _select_case_artifacts(
        manifest,
        categories=categories,
        exclude_categories=exclude_categories,
        source_commands=source_commands,
        device_serials=device_serials,
    )
    summary = summarize_case_manifest(
        case_dir,
        categories=categories,
        exclude_categories=exclude_categories,
        source_commands=source_commands,
        device_serials=device_serials,
    )
    graph = case_lineage_graph(
        case_dir,
        categories=categories,
        exclude_categories=exclude_categories,
        source_commands=source_commands,
        device_serials=device_serials,
    )
    integrity = case_integrity_report(case_dir, artifacts=selected_artifacts)
    chain_of_custody = generate_case_chain_of_custody(
        case_dir,
        notes="Generated automatically during case bundle export.",
        artifacts=selected_artifacts,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    written_arc_names: set[str] = set()
    included_paths: set[str] = set()
    included_artifact_ids: list[str] = []
    missing_registered_artifacts: list[dict[str, str]] = []

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for required in (_manifest_path(case_dir), case_dir / "logs", case_dir / "reports"):
            _add_path_to_zip(
                archive,
                source_path=required,
                bundle_root=bundle_root,
                case_dir=case_dir,
                written_arc_names=written_arc_names,
                included_paths=included_paths,
            )

        if include_registered_artifacts:
            for artifact in selected_artifacts:
                artifact_path = pathlib.Path(artifact.path)
                if not artifact_path.is_absolute():
                    artifact_path = case_dir / artifact.path
                if artifact_path.resolve() == output_path.resolve() or not artifact_path.exists():
                    missing_registered_artifacts.append({"artifact_id": artifact.artifact_id, "path": artifact.path})
                    continue
                _add_path_to_zip(
                    archive,
                    source_path=artifact_path,
                    bundle_root=bundle_root,
                    case_dir=case_dir,
                    written_arc_names=written_arc_names,
                    included_paths=included_paths,
                )
                included_artifact_ids.append(artifact.artifact_id)

        export_payload = {
            "case_dir": str(case_dir),
            "case_id": manifest.case_id,
            "title": manifest.title,
            "examiner": manifest.examiner,
            "workspace_root": manifest.workspace_root,
            "bundle_root": bundle_root,
            "bundle_path": str(output_path.resolve()),
            "exported_at_utc": _utc_now(),
            "include_registered_artifacts": include_registered_artifacts,
            "filters": _artifact_filter_payload(
                categories=categories,
                exclude_categories=exclude_categories,
                source_commands=source_commands,
                device_serials=device_serials,
            ),
            "selected_artifact_count": len(selected_artifacts),
            "total_artifact_count": len(manifest.artifacts),
            "included_paths": sorted(included_paths),
            "included_artifact_ids": sorted(set(included_artifact_ids)),
            "missing_registered_artifacts": missing_registered_artifacts,
            "summary": summary,
            "graph": graph,
            "integrity_summary": integrity["summary"],
            "chain_of_custody_entry_count": len(selected_artifacts),
        }
        archive.writestr(f"{bundle_root}/bundle/export_metadata.json", json.dumps(export_payload, indent=2, sort_keys=True))
        archive.writestr(f"{bundle_root}/bundle/case_summary.json", json.dumps(summary, indent=2, sort_keys=True))
        archive.writestr(f"{bundle_root}/bundle/case_graph.json", json.dumps(graph, indent=2, sort_keys=True))
        archive.writestr(f"{bundle_root}/bundle/integrity_report.json", json.dumps(integrity, indent=2, sort_keys=True))
        archive.writestr(f"{bundle_root}/bundle/chain_of_custody.txt", chain_of_custody)

    return export_payload
