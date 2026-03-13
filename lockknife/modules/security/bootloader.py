from __future__ import annotations

import dataclasses

from lockknife.core.device import DeviceManager


@dataclasses.dataclass(frozen=True)
class BootloaderStatus:
    serial: str
    oem_unlock_supported: str | None
    oem_unlock_allowed: str | None
    flash_locked: str | None
    verifiedbootstate: str | None
    vbmeta_device_state: str | None
    bootloader: str | None
    slot_suffix: str | None
    warranty_bit: str | None


def analyze_bootloader(devices: DeviceManager, serial: str) -> BootloaderStatus:
    props = devices.info(serial).props
    return BootloaderStatus(
        serial=serial,
        oem_unlock_supported=props.get("ro.oem_unlock_supported"),
        oem_unlock_allowed=props.get("sys.oem_unlock_allowed") or props.get("ro.oem_unlock_supported"),
        flash_locked=props.get("ro.boot.flash.locked"),
        verifiedbootstate=props.get("ro.boot.verifiedbootstate"),
        vbmeta_device_state=props.get("ro.boot.vbmeta.device_state"),
        bootloader=props.get("ro.boot.bootloader") or props.get("ro.bootloader"),
        slot_suffix=props.get("ro.boot.slot_suffix") or props.get("ro.boot.slot"),
        warranty_bit=props.get("ro.boot.warranty_bit"),
    )
