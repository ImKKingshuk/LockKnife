from __future__ import annotations

import dataclasses
from typing import Sequence

from lockknife.core.device import DeviceHandle, DeviceManager, DeviceState


@dataclasses.dataclass(frozen=True)
class DeviceReadinessReport:
    workflow: str
    selected_serial: str | None
    preferred_serial: str | None
    requested_serials: list[str]
    available_serials: list[str]
    authorized_serials: list[str]
    unavailable_serials: list[str]
    multiple_authorized: bool
    requires_root: bool
    root_available: bool | None
    guidance: list[str]


def build_device_readiness_report(
    devices: DeviceManager,
    *,
    workflow: str,
    serial: str | None = None,
    preferred_serial: str | None = None,
    target_serials: Sequence[str] | None = None,
    requires_root: bool = False,
) -> DeviceReadinessReport:
    handles = devices.list_handles()
    available = [handle.serial for handle in handles]
    authorized = [handle.serial for handle in handles if handle.state == DeviceState.authorized]
    requested = _unique_serials([serial, preferred_serial, *(target_serials or [])])
    unavailable = [value for value in requested if value not in available]
    selected = _selected_serial(serial, preferred_serial, target_serials, handles)
    root_available = devices.has_root(selected) if requires_root and selected else None
    guidance = _guidance(
        workflow=workflow,
        selected=selected,
        requested=requested,
        handles=handles,
        authorized=authorized,
        unavailable=unavailable,
        requires_root=requires_root,
        root_available=root_available,
    )
    return DeviceReadinessReport(
        workflow=workflow,
        selected_serial=selected,
        preferred_serial=_clean(preferred_serial),
        requested_serials=requested,
        available_serials=available,
        authorized_serials=authorized,
        unavailable_serials=unavailable,
        multiple_authorized=len(authorized) > 1,
        requires_root=requires_root,
        root_available=root_available,
        guidance=guidance,
    )


def _selected_serial(
    serial: str | None,
    preferred_serial: str | None,
    target_serials: Sequence[str] | None,
    handles: Sequence[DeviceHandle],
) -> str | None:
    available = {handle.serial for handle in handles}
    for candidate in _unique_serials([serial, preferred_serial, *(target_serials or [])]):
        if candidate in available:
            return candidate
    return None


def _guidance(
    *,
    workflow: str,
    selected: str | None,
    requested: list[str],
    handles: Sequence[DeviceHandle],
    authorized: list[str],
    unavailable: list[str],
    requires_root: bool,
    root_available: bool | None,
) -> list[str]:
    lines: list[str] = []
    if not handles:
        lines.append(
            f"No ADB devices are visible for {workflow}. Run `lockknife device list` and confirm USB or Wi-Fi debugging before retrying."
        )
        return lines
    if unavailable:
        lines.append(
            "Requested targets are not currently visible: "
            + ", ".join(unavailable)
            + ". Refresh the device inventory before running this workflow."
        )
    if not authorized:
        lines.append(
            f"Connected devices are present, but none are authorized for {workflow}. Accept the ADB prompt or unlock the device first."
        )
    elif len(authorized) > 1 and selected is None:
        lines.append(
            "Multiple authorized devices are connected: "
            + ", ".join(authorized)
            + ". Select one explicit serial to avoid targeting the wrong device."
        )
    elif len(authorized) > 1 and selected:
        lines.append(
            f"Multiple authorized devices are connected; {workflow} is locked to {selected} for this run."
        )
    if selected:
        handle = next((item for item in handles if item.serial == selected), None)
        if handle is not None and handle.state != DeviceState.authorized:
            lines.append(
                f"Selected device {selected} is currently {handle.adb_state}. Authorize or reconnect it before retrying."
            )
    if requires_root and selected and root_available is False:
        lines.append(
            f"Selected device {selected} does not expose root access; this workflow depends on privileged file access."
        )
    if requires_root and selected and root_available is True:
        lines.append(f"Root access is available on {selected}; deeper credential artifacts should be readable.")
    if requested and not selected and authorized:
        lines.append(
            "Requested target preference did not resolve to an authorized device. Available authorized serials: "
            + ", ".join(authorized)
            + "."
        )
    return lines


def _unique_serials(values: Sequence[str | None]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        cleaned = _clean(value)
        if cleaned is None or cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
    return out


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None