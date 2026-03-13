from __future__ import annotations



import dataclasses

import json

import pathlib

from typing import Any



from lockknife.core._case_common import (
    _json_safe_value,
    _normalize_case_path,
    _sha256_file,
    _utc_now,
    load_case_manifest,
    save_case_manifest,
)

from lockknife.core._case_models import CaseArtifact, CaseArtifactRegistration, CaseManifest



def _artifact_ids_for_paths(manifest: CaseManifest, *, case_dir: pathlib.Path, paths: list[str]) -> list[str]:
    wanted = {_normalize_case_path(case_dir, p) for p in paths}
    return [artifact.artifact_id for artifact in manifest.artifacts if artifact.path in wanted]

def find_case_artifact(case_dir: pathlib.Path, *, path: str | pathlib.Path) -> CaseArtifact | None:
    manifest = load_case_manifest(case_dir)
    wanted = _normalize_case_path(case_dir, path)
    return next((artifact for artifact in reversed(manifest.artifacts) if artifact.path == wanted), None)

def find_case_artifact_by_id(case_dir: pathlib.Path, *, artifact_id: str) -> CaseArtifact | None:
    manifest = load_case_manifest(case_dir)
    return next((artifact for artifact in manifest.artifacts if artifact.artifact_id == artifact_id), None)

def _sorted_filter_values(values: list[str] | tuple[str, ...] | None) -> list[str]:
    return sorted({value for value in values or [] if value})

def _artifact_filter_payload(
    *,
    categories: list[str] | tuple[str, ...] | None = None,
    exclude_categories: list[str] | tuple[str, ...] | None = None,
    source_commands: list[str] | tuple[str, ...] | None = None,
    device_serials: list[str] | tuple[str, ...] | None = None,
) -> dict[str, list[str]]:
    return {
        "categories": _sorted_filter_values(categories),
        "exclude_categories": _sorted_filter_values(exclude_categories),
        "source_commands": _sorted_filter_values(source_commands),
        "device_serials": _sorted_filter_values(device_serials),
    }

def _select_case_artifacts(
    manifest: CaseManifest,
    *,
    categories: list[str] | tuple[str, ...] | None = None,
    exclude_categories: list[str] | tuple[str, ...] | None = None,
    source_commands: list[str] | tuple[str, ...] | None = None,
    device_serials: list[str] | tuple[str, ...] | None = None,
) -> list[CaseArtifact]:
    filters = _artifact_filter_payload(
        categories=categories,
        exclude_categories=exclude_categories,
        source_commands=source_commands,
        device_serials=device_serials,
    )

    def _matches(artifact: CaseArtifact) -> bool:
        if filters["categories"] and artifact.category not in filters["categories"]:
            return False
        if filters["exclude_categories"] and artifact.category in filters["exclude_categories"]:
            return False
        if filters["source_commands"] and artifact.source_command not in filters["source_commands"]:
            return False
        device_name = artifact.device_serial or "unknown"
        if filters["device_serials"] and device_name not in filters["device_serials"]:
            return False
        return True

    return [artifact for artifact in manifest.artifacts if _matches(artifact)]

def _latest_artifact_index_for_path(manifest: CaseManifest, *, stored_path: str) -> int | None:
    for idx in range(len(manifest.artifacts) - 1, -1, -1):
        if manifest.artifacts[idx].path == stored_path:
            return idx
    return None

def _artifact_registration_identity_matches(
    artifact: CaseArtifact,
    *,
    category: str,
    source_command: str,
    device_serial: str | None,
) -> bool:
    return artifact.category == category and artifact.source_command == source_command and artifact.device_serial == device_serial

def _artifact_registration_payload_matches(
    artifact: CaseArtifact,
    *,
    category: str,
    source_command: str,
    sha256: str,
    size_bytes: int,
    device_serial: str | None,
    input_paths: list[str],
    parent_artifact_ids: list[str],
    metadata: dict[str, Any],
) -> bool:
    return (
        artifact.category == category
        and artifact.source_command == source_command
        and artifact.sha256 == sha256
        and artifact.size_bytes == size_bytes
        and artifact.device_serial == device_serial
        and artifact.input_paths == input_paths
        and artifact.parent_artifact_ids == parent_artifact_ids
        and artifact.metadata == metadata
    )

def _artifact_matches_text(artifact: CaseArtifact, *, query: str | None = None, path_contains: str | None = None, metadata_contains: str | None = None) -> bool:
    if query:
        needle = query.lower()
        haystacks = [
            artifact.artifact_id,
            artifact.path,
            artifact.category,
            artifact.source_command,
            artifact.device_serial or "unknown",
            json.dumps(artifact.metadata, sort_keys=True),
        ]
        if not any(needle in value.lower() for value in haystacks):
            return False
    if path_contains and path_contains.lower() not in artifact.path.lower():
        return False
    if metadata_contains and metadata_contains.lower() not in json.dumps(artifact.metadata, sort_keys=True).lower():
        return False
    return True

def _artifact_summary_payload(artifact: CaseArtifact) -> dict[str, Any]:
    return {
        "artifact_id": artifact.artifact_id,
        "path": artifact.path,
        "category": artifact.category,
        "source_command": artifact.source_command,
        "device_serial": artifact.device_serial,
        "size_bytes": artifact.size_bytes,
        "created_at_utc": artifact.created_at_utc,
        "parent_artifact_ids": artifact.parent_artifact_ids,
        "input_paths": artifact.input_paths,
    }

def query_case_artifacts(
    case_dir: pathlib.Path,
    *,
    categories: list[str] | tuple[str, ...] | None = None,
    exclude_categories: list[str] | tuple[str, ...] | None = None,
    source_commands: list[str] | tuple[str, ...] | None = None,
    device_serials: list[str] | tuple[str, ...] | None = None,
    query: str | None = None,
    path_contains: str | None = None,
    metadata_contains: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    manifest = load_case_manifest(case_dir)
    artifacts = _select_case_artifacts(
        manifest,
        categories=categories,
        exclude_categories=exclude_categories,
        source_commands=source_commands,
        device_serials=device_serials,
    )
    matched = [
        artifact
        for artifact in artifacts
        if _artifact_matches_text(artifact, query=query, path_contains=path_contains, metadata_contains=metadata_contains)
    ]
    if limit is not None:
        matched = matched[:limit]
    return {
        "case_dir": str(case_dir),
        "case_id": manifest.case_id,
        "title": manifest.title,
        "examiner": manifest.examiner,
        "artifact_count": len(matched),
        "total_artifact_count": len(manifest.artifacts),
        "filters": _artifact_filter_payload(
            categories=categories,
            exclude_categories=exclude_categories,
            source_commands=source_commands,
            device_serials=device_serials,
        ),
        "search": {
            "query": query,
            "path_contains": path_contains,
            "metadata_contains": metadata_contains,
            "limit": limit,
        },
        "artifacts": [_artifact_summary_payload(artifact) for artifact in matched],
    }

def case_artifact_details(
    case_dir: pathlib.Path,
    *,
    artifact_id: str | None = None,
    path: str | pathlib.Path | None = None,
) -> dict[str, Any] | None:
    manifest = load_case_manifest(case_dir)
    artifact: CaseArtifact | None = None
    if artifact_id is not None:
        artifact = next((item for item in manifest.artifacts if item.artifact_id == artifact_id), None)
    elif path is not None:
        wanted = _normalize_case_path(case_dir, path)
        artifact = next((item for item in reversed(manifest.artifacts) if item.path == wanted), None)
    if artifact is None:
        return None

    child_artifacts = [item for item in manifest.artifacts if artifact.artifact_id in item.parent_artifact_ids]
    parent_map = {item.artifact_id: item for item in manifest.artifacts}
    parent_artifacts = [parent_map[parent_id] for parent_id in artifact.parent_artifact_ids if parent_id in parent_map]
    missing_parent_ids = [parent_id for parent_id in artifact.parent_artifact_ids if parent_id not in parent_map]

    return {
        "case_dir": str(case_dir),
        "case_id": manifest.case_id,
        "title": manifest.title,
        "examiner": manifest.examiner,
        "artifact": dataclasses.asdict(artifact),
        "parents": [_artifact_summary_payload(item) for item in parent_artifacts],
        "children": [_artifact_summary_payload(item) for item in child_artifacts],
        "missing_parent_ids": missing_parent_ids,
    }

def case_artifact_lineage(
    case_dir: pathlib.Path,
    *,
    artifact_id: str | None = None,
    path: str | pathlib.Path | None = None,
) -> dict[str, Any] | None:
    payload = case_artifact_details(case_dir, artifact_id=artifact_id, path=path)
    if payload is None:
        return None
    artifact = payload["artifact"]
    return {
        "case_dir": str(case_dir),
        "case_id": payload["case_id"],
        "title": payload["title"],
        "examiner": payload["examiner"],
        "artifact": _artifact_summary_payload(CaseArtifact(**artifact)),
        "parents": payload["parents"],
        "children": payload["children"],
        "missing_parent_ids": payload["missing_parent_ids"],
    }

def register_case_artifact(
    *,
    case_dir: pathlib.Path,
    path: pathlib.Path,
    category: str,
    source_command: str,
    device_serial: str | None = None,
    input_paths: list[str] | None = None,
    parent_artifact_ids: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    on_conflict: str = "auto",
) -> CaseArtifact:
    return register_case_artifact_with_status(
        case_dir=case_dir,
        path=path,
        category=category,
        source_command=source_command,
        device_serial=device_serial,
        input_paths=input_paths,
        parent_artifact_ids=parent_artifact_ids,
        metadata=metadata,
        on_conflict=on_conflict,
    ).artifact

def register_case_artifact_with_status(
    *,
    case_dir: pathlib.Path,
    path: pathlib.Path,
    category: str,
    source_command: str,
    device_serial: str | None = None,
    input_paths: list[str] | None = None,
    parent_artifact_ids: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    on_conflict: str = "auto",
) -> CaseArtifactRegistration:
    if on_conflict not in {"auto", "replace", "duplicate", "error"}:
        raise ValueError(f"Unsupported on_conflict mode: {on_conflict}")

    manifest = load_case_manifest(case_dir)
    resolved = path.resolve()
    sha256, size_bytes = _sha256_file(resolved)
    created_at = _utc_now()
    normalized_input_paths = [_normalize_case_path(case_dir, p) for p in list(input_paths or [])]
    resolved_parent_ids = list(parent_artifact_ids or [])
    for artifact_id in _artifact_ids_for_paths(manifest, case_dir=case_dir, paths=normalized_input_paths):
        if artifact_id not in resolved_parent_ids:
            resolved_parent_ids.append(artifact_id)
    try:
        stored_path = str(resolved.relative_to(case_dir.resolve()))
    except ValueError:
        stored_path = str(resolved)

    resolved_metadata = dict(metadata or {})
    existing_idx = _latest_artifact_index_for_path(manifest, stored_path=stored_path)
    existing_artifact = manifest.artifacts[existing_idx] if existing_idx is not None else None

    if existing_artifact is not None:
        if on_conflict == "error":
            raise ValueError(f"Artifact path already registered: {stored_path} ({existing_artifact.artifact_id})")

        if on_conflict == "auto" and not _artifact_registration_identity_matches(
            existing_artifact,
            category=category,
            source_command=source_command,
            device_serial=device_serial,
        ):
            raise ValueError(
                "Artifact path collision for "
                f"{stored_path}: existing={existing_artifact.artifact_id} "
                f"[{existing_artifact.category} via {existing_artifact.source_command}] "
                "Use on_conflict='replace' or 'duplicate' to override."
            )

        if on_conflict in {"auto", "replace"}:
            if existing_idx is None:
                raise RuntimeError("artifact conflict index missing")
            if _artifact_registration_payload_matches(
                existing_artifact,
                category=category,
                source_command=source_command,
                sha256=sha256,
                size_bytes=size_bytes,
                device_serial=device_serial,
                input_paths=normalized_input_paths,
                parent_artifact_ids=resolved_parent_ids,
                metadata=resolved_metadata,
            ):
                return CaseArtifactRegistration(artifact=existing_artifact, action="reused")

            updated_artifact = dataclasses.replace(
                existing_artifact,
                category=category,
                source_command=source_command,
                sha256=sha256,
                size_bytes=size_bytes,
                created_at_utc=created_at,
                device_serial=device_serial,
                input_paths=normalized_input_paths,
                parent_artifact_ids=resolved_parent_ids,
                metadata=resolved_metadata,
            )
            manifest.artifacts[existing_idx] = updated_artifact
            manifest.updated_at_utc = created_at
            save_case_manifest(case_dir, manifest)
            return CaseArtifactRegistration(artifact=updated_artifact, action="updated")

    artifact = CaseArtifact(
        artifact_id=f"artifact-{len(manifest.artifacts) + 1:04d}",
        path=stored_path,
        category=category,
        source_command=source_command,
        sha256=sha256,
        size_bytes=size_bytes,
        created_at_utc=created_at,
        device_serial=device_serial,
        input_paths=normalized_input_paths,
        parent_artifact_ids=resolved_parent_ids,
        metadata=resolved_metadata,
    )
    manifest.artifacts.append(artifact)
    manifest.updated_at_utc = created_at
    save_case_manifest(case_dir, manifest)
    return CaseArtifactRegistration(artifact=artifact, action="created")
