from __future__ import annotations

import dataclasses
import pathlib
from typing import Any, Callable

from lockknife.core.device_selection import resolve_single_device_serial
from lockknife.core.device_targeting import build_device_readiness_report


def run_pin_recovery_workflow(
    devices: Any,
    *,
    serial: str | None,
    length: int,
    case_dir: pathlib.Path | None,
    output_dir: pathlib.Path | None,
    preferred_serial: str | None = None,
    target_serials: list[str] | None = None,
    source_command: str,
    export_pin_recovery: Callable[..., Any],
    recover_pin: Callable[..., str],
    write_json: Callable[[pathlib.Path, Any], None],
    register_case_artifact: Callable[..., Any],
    load_case_manifest: Callable[[pathlib.Path], Any],
) -> dict[str, Any]:
    serial = _resolve_serial(
        devices,
        serial=serial,
        case_dir=case_dir,
        preferred_serial=preferred_serial,
        target_serials=target_serials,
        action_label="PIN recovery",
        load_case_manifest=load_case_manifest,
    )
    readiness = _readiness(devices, serial, source_command, requires_root=True)
    if output_dir is None and case_dir is None:
        pin = recover_pin(devices, serial, length)
        return {"serial": serial, "length": length, "pin": pin, "readiness": readiness}

    output_dir = _workflow_dir(output_dir, case_dir, f"pin_{serial}")
    recovery = export_pin_recovery(devices, serial, length, output_dir)
    payload = {
        "serial": serial,
        "length": length,
        "pin": recovery.pin,
        "salt": recovery.salt,
        "password_key_sha1": recovery.password_key_sha1,
        "locksettings_db_path": str(recovery.locksettings_db_path),
        "password_key_path": str(recovery.password_key_path),
        "readiness": readiness,
    }
    manifest_path = output_dir / "pin_recovery.json"
    write_json(manifest_path, payload)
    parent_ids = _register_sources(
        case_dir,
        register_case_artifact,
        source_command,
        serial,
        [
            (recovery.locksettings_db_path, "crack-pin-locksettings", {"format": "sqlite"}),
            (recovery.password_key_path, "crack-pin-password-key", {"format": "binary"}),
        ],
    )
    manifest_artifact_id = _register_manifest(
        case_dir,
        register_case_artifact,
        manifest_path,
        category="crack-pin-manifest",
        source_command=source_command,
        serial=serial,
        parent_artifact_ids=parent_ids,
        metadata={"length": length},
    )
    payload.update(_artifact_payload(manifest_path, case_dir, manifest_artifact_id, parent_ids))
    return payload


def run_gesture_recovery_workflow(
    devices: Any,
    *,
    serial: str | None,
    case_dir: pathlib.Path | None,
    output_dir: pathlib.Path | None,
    preferred_serial: str | None = None,
    target_serials: list[str] | None = None,
    source_command: str,
    export_gesture_recovery: Callable[..., Any],
    recover_gesture: Callable[..., str],
    write_json: Callable[[pathlib.Path, Any], None],
    register_case_artifact: Callable[..., Any],
    load_case_manifest: Callable[[pathlib.Path], Any],
) -> dict[str, Any]:
    serial = _resolve_serial(
        devices,
        serial=serial,
        case_dir=case_dir,
        preferred_serial=preferred_serial,
        target_serials=target_serials,
        action_label="gesture recovery",
        load_case_manifest=load_case_manifest,
    )
    readiness = _readiness(devices, serial, source_command, requires_root=True)
    if output_dir is None and case_dir is None:
        pattern = recover_gesture(devices, serial)
        return {"serial": serial, "gesture": pattern, "readiness": readiness}

    output_dir = _workflow_dir(output_dir, case_dir, f"gesture_{serial}")
    recovery = export_gesture_recovery(devices, serial, output_dir)
    payload = {
        "serial": serial,
        "gesture": recovery.pattern,
        "point_count": recovery.point_count,
        "key_path": str(recovery.key_path),
        "key_size": recovery.key_size,
        "source_remote_path": recovery.source_remote_path,
        "readiness": readiness,
    }
    manifest_path = output_dir / "gesture_recovery.json"
    write_json(manifest_path, payload)
    parent_ids = _register_sources(
        case_dir,
        register_case_artifact,
        source_command,
        serial,
        [(recovery.key_path, "crack-gesture-key", {"remote_path": recovery.source_remote_path, "size": recovery.key_size})],
    )
    manifest_artifact_id = _register_manifest(
        case_dir,
        register_case_artifact,
        manifest_path,
        category="crack-gesture-manifest",
        source_command=source_command,
        serial=serial,
        parent_artifact_ids=parent_ids,
        metadata={"point_count": recovery.point_count},
    )
    payload.update(_artifact_payload(manifest_path, case_dir, manifest_artifact_id, parent_ids))
    return payload


def run_wifi_workflow(
    devices: Any,
    *,
    serial: str | None,
    case_dir: pathlib.Path | None,
    output_dir: pathlib.Path | None,
    preferred_serial: str | None = None,
    target_serials: list[str] | None = None,
    source_command: str,
    export_wifi_credentials: Callable[..., Any],
    extract_wifi_passwords: Callable[..., Any],
    write_json: Callable[[pathlib.Path, Any], None],
    register_case_artifact: Callable[..., Any],
    load_case_manifest: Callable[[pathlib.Path], Any],
) -> dict[str, Any]:
    serial = _resolve_serial(
        devices,
        serial=serial,
        case_dir=case_dir,
        preferred_serial=preferred_serial,
        target_serials=target_serials,
        action_label="WiFi credential recovery",
        load_case_manifest=load_case_manifest,
    )
    readiness = _readiness(devices, serial, source_command, requires_root=True)
    if output_dir is None and case_dir is None:
        rows = [dataclasses.asdict(row) for row in extract_wifi_passwords(devices, serial)]
        return {"serial": serial, "credentials": rows, "credential_count": len(rows), "readiness": readiness}

    output_dir = _workflow_dir(output_dir, case_dir, f"wifi_{serial}")
    extraction = export_wifi_credentials(devices, serial, output_dir)
    rows = [dataclasses.asdict(row) for row in extraction.credentials]
    payload = {
        "serial": serial,
        "credentials": rows,
        "credential_count": len(rows),
        "source_remote_path": extraction.source_remote_path,
        "source_local_path": str(extraction.source_local_path),
        "candidate_paths": extraction.candidate_paths,
        "readiness": readiness,
    }
    manifest_path = output_dir / "wifi_credentials.json"
    write_json(manifest_path, payload)
    parent_ids = _register_sources(
        case_dir,
        register_case_artifact,
        source_command,
        serial,
        [(extraction.source_local_path, "crack-wifi-config", {"remote_path": extraction.source_remote_path})],
    )
    manifest_artifact_id = _register_manifest(
        case_dir,
        register_case_artifact,
        manifest_path,
        category="crack-wifi-manifest",
        source_command=source_command,
        serial=serial,
        parent_artifact_ids=parent_ids,
        metadata={"credential_count": len(rows), "source_remote_path": extraction.source_remote_path},
    )
    payload.update(_artifact_payload(manifest_path, case_dir, manifest_artifact_id, parent_ids))
    return payload


def run_keystore_workflow(
    devices: Any,
    *,
    serial: str | None,
    case_dir: pathlib.Path | None,
    output_dir: pathlib.Path | None,
    preferred_serial: str | None = None,
    target_serials: list[str] | None = None,
    source_command: str,
    inspect_keystore: Callable[..., Any],
    list_keystore: Callable[..., Any],
    write_json: Callable[[pathlib.Path, Any], None],
    register_case_artifact: Callable[..., Any],
    load_case_manifest: Callable[[pathlib.Path], Any],
) -> dict[str, Any]:
    serial = _resolve_serial(
        devices,
        serial=serial,
        case_dir=case_dir,
        preferred_serial=preferred_serial,
        target_serials=target_serials,
        action_label="keystore inventory",
        load_case_manifest=load_case_manifest,
    )
    readiness = _readiness(devices, serial, source_command, requires_root=True)
    if output_dir is None and case_dir is None:
        rows = [dataclasses.asdict(row) for row in list_keystore(devices, serial)]
        return {"serial": serial, "listings": rows, "listing_count": len(rows), "readiness": readiness}

    output_dir = _workflow_dir(output_dir, case_dir, f"keystore_{serial}")
    inventory = inspect_keystore(devices, serial)
    rows = [dataclasses.asdict(row) for row in inventory.listings]
    payload = {
        "serial": serial,
        "listings": rows,
        "listing_count": len(rows),
        "candidate_paths": inventory.candidate_paths,
        "readiness": readiness,
    }
    manifest_path = output_dir / "keystore_inventory.json"
    write_json(manifest_path, payload)
    manifest_artifact_id = _register_manifest(
        case_dir,
        register_case_artifact,
        manifest_path,
        category="crack-keystore-manifest",
        source_command=source_command,
        serial=serial,
        parent_artifact_ids=[],
        metadata={"listing_count": len(rows)},
    )
    payload.update(_artifact_payload(manifest_path, case_dir, manifest_artifact_id, []))
    return payload


def run_passkey_workflow(
    devices: Any,
    *,
    serial: str | None,
    case_dir: pathlib.Path | None,
    output_dir: pathlib.Path | None,
    limit: int,
    preferred_serial: str | None = None,
    target_serials: list[str] | None = None,
    source_command: str,
    pull_passkey_artifacts: Callable[..., Any],
    write_json: Callable[[pathlib.Path, Any], None],
    register_case_artifact: Callable[..., Any],
    load_case_manifest: Callable[[pathlib.Path], Any],
) -> dict[str, Any]:
    if output_dir is None and case_dir is None:
        raise ValueError("Either output_dir or case_dir is required for passkey export")
    serial = _resolve_serial(
        devices,
        serial=serial,
        case_dir=case_dir,
        preferred_serial=preferred_serial,
        target_serials=target_serials,
        action_label="passkey export",
        load_case_manifest=load_case_manifest,
    )
    readiness = _readiness(devices, serial, source_command, requires_root=True)
    output_dir = _workflow_dir(output_dir, case_dir, f"passkeys_{serial}")
    items = pull_passkey_artifacts(devices, serial, output_dir=output_dir, limit=limit)
    rows = [
        dataclasses.asdict(item) if dataclasses.is_dataclass(item) and not isinstance(item, type) else dict(item)
        for item in items
    ]
    success_count = sum(1 for item in rows if item.get("local_path"))
    payload = {
        "serial": serial,
        "limit": limit,
        "artifacts": rows,
        "artifact_count": len(rows),
        "success_count": success_count,
        "failed_count": len(rows) - success_count,
        "readiness": readiness,
    }
    manifest_path = output_dir / "passkeys_manifest.json"
    write_json(manifest_path, payload)
    parent_ids: list[str] = []
    if case_dir is not None:
        for item in rows:
            local_path = item.get("local_path")
            if not local_path:
                continue
            artifact = register_case_artifact(
                case_dir=case_dir,
                path=pathlib.Path(local_path),
                category="crack-passkey-artifact",
                source_command=source_command,
                device_serial=serial,
                metadata={"remote_path": item.get("remote_path"), "size": item.get("size")},
            )
            artifact_id = getattr(artifact, "artifact_id", None)
            if isinstance(artifact_id, str):
                parent_ids.append(artifact_id)
    manifest_artifact_id = _register_manifest(
        case_dir,
        register_case_artifact,
        manifest_path,
        category="crack-passkeys-manifest",
        source_command=source_command,
        serial=serial,
        parent_artifact_ids=parent_ids,
        metadata={"limit": limit, "artifact_count": len(rows), "success_count": success_count},
    )
    payload.update(_artifact_payload(manifest_path, case_dir, manifest_artifact_id, parent_ids))
    return payload


def _resolve_serial(
    devices: Any,
    *,
    serial: str | None,
    case_dir: pathlib.Path | None,
    preferred_serial: str | None,
    target_serials: list[str] | None,
    action_label: str,
    load_case_manifest: Callable[[pathlib.Path], Any],
) -> str:
    case_targets = list(target_serials or [])
    if case_dir is not None and not case_targets:
        case_targets = list(getattr(load_case_manifest(case_dir), "target_serials", []) or [])
    return resolve_single_device_serial(
        devices,
        serial=serial,
        preferred_serial=preferred_serial,
        target_serials=case_targets,
        action_label=action_label,
    )


def _readiness(devices: Any, serial: str, source_command: str, *, requires_root: bool) -> dict[str, Any]:
    return dataclasses.asdict(
        build_device_readiness_report(
            devices,
            workflow=source_command,
            serial=serial,
            requires_root=requires_root,
        )
    )


def _workflow_dir(output_dir: pathlib.Path | None, case_dir: pathlib.Path | None, name: str) -> pathlib.Path:
    if output_dir is not None:
        target = output_dir
    else:
        if case_dir is None:
            raise ValueError("case_dir is required when output_dir is not provided")
        target = case_dir / "evidence" / name
    target.mkdir(parents=True, exist_ok=True)
    return target


def _register_sources(
    case_dir: pathlib.Path | None,
    register_case_artifact: Callable[..., Any],
    source_command: str,
    serial: str,
    entries: list[tuple[pathlib.Path, str, dict[str, Any]]],
) -> list[str]:
    if case_dir is None:
        return []
    parent_ids: list[str] = []
    for path, category, metadata in entries:
        artifact = register_case_artifact(
            case_dir=case_dir,
            path=path,
            category=category,
            source_command=source_command,
            device_serial=serial,
            metadata=metadata,
        )
        artifact_id = getattr(artifact, "artifact_id", None)
        if artifact_id:
            parent_ids.append(artifact_id)
    return parent_ids


def _register_manifest(
    case_dir: pathlib.Path | None,
    register_case_artifact: Callable[..., Any],
    manifest_path: pathlib.Path,
    *,
    category: str,
    source_command: str,
    serial: str,
    parent_artifact_ids: list[str],
    metadata: dict[str, Any],
) -> str | None:
    if case_dir is None:
        return None
    artifact = register_case_artifact(
        case_dir=case_dir,
        path=manifest_path,
        category=category,
        source_command=source_command,
        device_serial=serial,
        parent_artifact_ids=parent_artifact_ids,
        metadata=metadata,
    )
    return getattr(artifact, "artifact_id", None)


def _artifact_payload(
    manifest_path: pathlib.Path,
    case_dir: pathlib.Path | None,
    manifest_artifact_id: str | None,
    parent_artifact_ids: list[str],
) -> dict[str, Any]:
    payload: dict[str, Any] = {"manifest_path": str(manifest_path), "parent_artifact_ids": parent_artifact_ids}
    if case_dir is not None:
        payload["case_dir"] = str(case_dir)
    if manifest_artifact_id:
        payload["manifest_artifact_id"] = manifest_artifact_id
    return payload