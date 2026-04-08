from __future__ import annotations

from collections.abc import Mapping, Sequence

from lockknife.core.device import DeviceManager, DeviceState
from lockknife.core.device_targeting import build_device_readiness_report
from lockknife.core.exceptions import DeviceError


def normalize_target_serials(value: str | Sequence[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = value.split(",")
    else:
        items = []
        for entry in value:
            items.extend(str(entry).split(","))
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        cleaned = item.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
    return out


def resolve_single_device_serial(
    devices: DeviceManager,
    *,
    serial: str | None = None,
    preferred_serial: str | None = None,
    target_serials: str | Sequence[str] | None = None,
    action_label: str = "device workflow",
) -> str:
    explicit = _clean(serial)
    preferred = _clean(preferred_serial)
    targets = normalize_target_serials(target_serials)
    handles = {handle.serial: handle for handle in devices.list_handles()}
    authorized = [
        handle.serial for handle in handles.values() if handle.state == DeviceState.authorized
    ]
    report = build_device_readiness_report(
        devices,
        workflow=action_label,
        serial=explicit,
        preferred_serial=preferred,
        target_serials=targets,
    )

    if explicit is not None:
        return _require_authorized(handles, authorized, explicit, action_label)
    if preferred is not None and preferred in authorized:
        return preferred

    matched_targets = [item for item in targets if item in authorized]
    if len(targets) > 1:
        if preferred and preferred in matched_targets:
            return preferred
        if len(matched_targets) == 1:
            return matched_targets[0]
        raise DeviceError(
            f"{action_label} targets one device at a time, but the current target set contains multiple serials: {', '.join(targets)}. Choose one explicit serial."
        )
    if len(matched_targets) == 1:
        return matched_targets[0]
    if len(authorized) == 1:
        return authorized[0]
    if not handles:
        raise DeviceError(
            report.guidance[0] if report.guidance else f"No devices are ready for {action_label}"
        )
    if not authorized:
        raise DeviceError(
            report.guidance[0]
            if report.guidance
            else f"No authorized devices are ready for {action_label}."
        )
    raise DeviceError(
        f"Multiple authorized devices are available for {action_label}: {', '.join(authorized)}. Select one explicit serial."
    )


def _require_authorized(
    handles: Mapping[str, object], authorized: list[str], serial: str, action_label: str
) -> str:
    handle = handles.get(serial)
    if handle is None:
        visible = ", ".join(sorted(handles)) or "none"
        raise DeviceError(
            f"Requested serial {serial} is not currently visible for {action_label}. Visible serials: {visible}."
        )
    if serial not in authorized:
        adb_state = getattr(handle, "adb_state", getattr(handle, "state", "unknown"))
        raise DeviceError(
            f"Requested serial {serial} is currently {adb_state}. Authorize or reconnect it before running {action_label}."
        )
    return serial


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None
