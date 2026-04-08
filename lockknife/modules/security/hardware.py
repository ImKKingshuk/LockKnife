from __future__ import annotations

import dataclasses

from lockknife.core.device import DeviceManager


@dataclasses.dataclass(frozen=True)
class HardwareSecurityStatus:
    serial: str
    keystore_hw: str | None
    keymaster_hw: str | None
    gatekeeper_hw: str | None
    strongbox: bool
    fingerprint_hw: str | None
    face_hw: str | None
    knox: str | None


def analyze_hardware_security(devices: DeviceManager, serial: str) -> HardwareSecurityStatus:
    props = devices.info(serial).props
    ks = props.get("ro.hardware.keystore") or props.get("ro.hardware.keystore_des")
    km = props.get("ro.hardware.keymaster") or props.get("ro.hardware.keymaster_hal")
    gk = props.get("ro.hardware.gatekeeper")
    strongbox = False
    for k, v in props.items():
        if "strongbox" in k.lower() or "strongbox" in (v or "").lower():
            strongbox = True
            break
    fp = props.get("ro.hardware.fingerprint") or props.get("ro.hardware.biometrics.fingerprint")
    face = props.get("ro.hardware.biometrics.face")
    knox = (
        props.get("ro.config.knox")
        or props.get("ro.vendor.knox.version")
        or props.get("ro.boot.knox")
    )
    return HardwareSecurityStatus(
        serial=serial,
        keystore_hw=ks,
        keymaster_hw=km,
        gatekeeper_hw=gk,
        strongbox=bool(strongbox),
        fingerprint_hw=fp,
        face_hw=face,
        knox=knox,
    )
