from __future__ import annotations

import dataclasses
from typing import Any

from lockknife.core.device import DeviceManager
from lockknife.core.logging import get_logger

log = get_logger()


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
    # --- Batch 7: Verified Boot & AVB posture ---
    avb_version: str | None = None
    dm_verity_state: str | None = None
    anti_rollback_index: str | None = None
    vbmeta_hash_alg: str | None = None
    vbmeta_digest: str | None = None
    boot_reason: str | None = None
    secure_boot: str | None = None
    device_state: str | None = None
    hardware_revision: str | None = None
    posture: dict[str, Any] = dataclasses.field(default_factory=dict)
    remediation_hints: list[str] = dataclasses.field(default_factory=list)


def analyze_bootloader(devices: DeviceManager, serial: str) -> BootloaderStatus:
    props = devices.info(serial).props

    oem_unlock_supported = props.get("ro.oem_unlock_supported")
    oem_unlock_allowed = (
        props.get("sys.oem_unlock_allowed")
        or props.get("ro.oem_unlock_supported")
    )
    flash_locked = props.get("ro.boot.flash.locked")
    verifiedbootstate = props.get("ro.boot.verifiedbootstate")
    vbmeta_device_state = props.get("ro.boot.vbmeta.device_state")
    bootloader_version = props.get("ro.boot.bootloader") or props.get("ro.bootloader")
    slot_suffix = props.get("ro.boot.slot_suffix") or props.get("ro.boot.slot")
    warranty_bit = props.get("ro.boot.warranty_bit")

    # AVB / Android Verified Boot 2.0 properties
    avb_version = (
        props.get("ro.boot.avb_version")
        or props.get("ro.boot.vbmeta.avb_version")
    )
    dm_verity_state = (
        props.get("ro.boot.veritymode")
        or props.get("ro.boot.veritymode.managed")
    )
    anti_rollback_index = props.get("ro.boot.vbmeta.security_patch_level")
    vbmeta_hash_alg = props.get("ro.boot.vbmeta.hash_alg")
    vbmeta_digest = props.get("ro.boot.vbmeta.digest")
    boot_reason = props.get("ro.boot.bootreason") or props.get("sys.boot.reason")
    secure_boot = props.get("ro.boot.secureboot") or props.get("ro.secure")
    device_state = props.get("ro.boot.vbmeta.device_state") or props.get("ro.boot.device_state")
    hardware_revision = (
        props.get("ro.boot.hardware.revision")
        or props.get("ro.revision")
        or props.get("ro.boot.hardware.platform")
    )

    posture = _assess_boot_posture(
        oem_unlock_allowed=oem_unlock_allowed,
        flash_locked=flash_locked,
        verifiedbootstate=verifiedbootstate,
        vbmeta_device_state=vbmeta_device_state,
        dm_verity_state=dm_verity_state,
        avb_version=avb_version,
        secure_boot=secure_boot,
        warranty_bit=warranty_bit,
    )
    remediation_hints = _bootloader_remediation_hints(posture)

    return BootloaderStatus(
        serial=serial,
        oem_unlock_supported=oem_unlock_supported,
        oem_unlock_allowed=oem_unlock_allowed,
        flash_locked=flash_locked,
        verifiedbootstate=verifiedbootstate,
        vbmeta_device_state=vbmeta_device_state,
        bootloader=bootloader_version,
        slot_suffix=slot_suffix,
        warranty_bit=warranty_bit,
        avb_version=avb_version,
        dm_verity_state=dm_verity_state,
        anti_rollback_index=anti_rollback_index,
        vbmeta_hash_alg=vbmeta_hash_alg,
        vbmeta_digest=vbmeta_digest,
        boot_reason=boot_reason,
        secure_boot=secure_boot,
        device_state=device_state,
        hardware_revision=hardware_revision,
        posture=posture,
        remediation_hints=remediation_hints,
    )


def _assess_boot_posture(
    *,
    oem_unlock_allowed: str | None,
    flash_locked: str | None,
    verifiedbootstate: str | None,
    vbmeta_device_state: str | None,
    dm_verity_state: str | None,
    avb_version: str | None,
    secure_boot: str | None,
    warranty_bit: str | None,
) -> dict[str, Any]:
    """Derive a composite risk posture from all available Verified Boot signals."""
    findings: list[dict[str, str]] = []
    risk_score = 0

    # --- Verified Boot State ---
    vbs = (verifiedbootstate or "").lower().strip()
    if vbs == "green":
        findings.append({"signal": "verified_boot_state", "value": "green", "severity": "ok",
                         "detail": "Boot chain is fully verified with OEM-signed images."})
    elif vbs == "yellow":
        findings.append({"signal": "verified_boot_state", "value": "yellow", "severity": "warning",
                         "detail": "Boot chain verified with user-installed root of trust (custom key)."})
        risk_score += 2
    elif vbs == "orange":
        findings.append({"signal": "verified_boot_state", "value": "orange", "severity": "high",
                         "detail": "Bootloader is unlocked; boot image signature enforcement is disabled."})
        risk_score += 4
    elif vbs == "red":
        findings.append({"signal": "verified_boot_state", "value": "red", "severity": "critical",
                         "detail": "Boot verification failed; device may be running tampered firmware."})
        risk_score += 6
    elif vbs:
        findings.append({"signal": "verified_boot_state", "value": vbs, "severity": "info",
                         "detail": f"Non-standard verified boot state: {vbs}"})
        risk_score += 1

    # --- OEM Unlock ---
    oem = (oem_unlock_allowed or "").strip()
    if oem == "1":
        findings.append({"signal": "oem_unlock_allowed", "value": "enabled", "severity": "warning",
                         "detail": "OEM unlock is permitted; bootloader can be unlocked from fastboot."})
        risk_score += 2
    elif oem == "0":
        findings.append({"signal": "oem_unlock_allowed", "value": "disabled", "severity": "ok",
                         "detail": "OEM unlock is disabled in developer settings."})

    # --- Flash Lock ---
    fl = (flash_locked or "").strip()
    if fl == "0":
        findings.append({"signal": "flash_locked", "value": "unlocked", "severity": "high",
                         "detail": "Flash lock is disengaged; firmware partitions can be overwritten."})
        risk_score += 4
    elif fl == "1":
        findings.append({"signal": "flash_locked", "value": "locked", "severity": "ok",
                         "detail": "Flash lock is engaged; firmware partitions are protected."})

    # --- vbmeta Device State ---
    vds = (vbmeta_device_state or "").lower().strip()
    if vds == "unlocked":
        findings.append({"signal": "vbmeta_device_state", "value": "unlocked", "severity": "high",
                         "detail": "vbmeta reports unlocked state; AVB enforcement is weakened."})
        risk_score += 3
    elif vds == "locked":
        findings.append({"signal": "vbmeta_device_state", "value": "locked", "severity": "ok",
                         "detail": "vbmeta reports locked state; AVB verification is active."})

    # --- dm-verity ---
    dv = (dm_verity_state or "").lower().strip()
    if dv in {"enforcing", "true", "1"}:
        findings.append({"signal": "dm_verity", "value": "enforcing", "severity": "ok",
                         "detail": "dm-verity is enforcing; partition integrity is validated at runtime."})
    elif dv in {"disabled", "false", "0", "logging"}:
        findings.append({"signal": "dm_verity", "value": dv, "severity": "high",
                         "detail": f"dm-verity is {dv}; runtime partition integrity verification is absent."})
        risk_score += 3

    # --- AVB version ---
    if avb_version:
        findings.append({"signal": "avb_version", "value": avb_version, "severity": "info",
                         "detail": f"Android Verified Boot version {avb_version} is present."})
    else:
        findings.append({"signal": "avb_version", "value": "absent", "severity": "warning",
                         "detail": "No AVB version property detected; device may use legacy boot verification."})
        risk_score += 1

    # --- Secure Boot flag ---
    sb = (secure_boot or "").strip()
    if sb in {"1", "true"}:
        findings.append({"signal": "secure_boot", "value": "enabled", "severity": "ok",
                         "detail": "Platform secure boot flag is set."})
    elif sb in {"0", "false"}:
        findings.append({"signal": "secure_boot", "value": "disabled", "severity": "high",
                         "detail": "Platform secure boot flag reports disabled."})
        risk_score += 3

    # --- Warranty bit ---
    wb = (warranty_bit or "").strip()
    if wb == "1":
        findings.append({"signal": "warranty_bit", "value": "tripped", "severity": "warning",
                         "detail": "Warranty bit is tripped; device has been modified or unlocked at some point."})
        risk_score += 1
    elif wb == "0":
        findings.append({"signal": "warranty_bit", "value": "intact", "severity": "ok",
                         "detail": "Warranty bit is intact."})

    # --- Overall risk level ---
    if risk_score >= 8:
        risk_level = "critical"
        assessment = "Multiple boot chain integrity signals are compromised; treat all on-device evidence as potentially tampered."
    elif risk_score >= 5:
        risk_level = "high"
        assessment = "Boot chain shows material weakening; firmware and partition integrity should not be assumed."
    elif risk_score >= 2:
        risk_level = "medium"
        assessment = "Some boot chain signals are non-default; review findings before trusting platform integrity."
    else:
        risk_level = "low"
        assessment = "Boot chain appears intact with standard OEM-verified configuration."

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "assessment": assessment,
        "findings": findings,
        "finding_count": len(findings),
    }


def _bootloader_remediation_hints(posture: dict[str, Any]) -> list[str]:
    """Generate actionable remediation hints based on posture findings."""
    hints: list[str] = []
    findings = posture.get("findings") or []

    for f in findings:
        severity = f.get("severity", "")
        signal = f.get("signal", "")

        if severity in {"critical", "high"}:
            if signal == "verified_boot_state":
                hints.append(
                    "Re-lock the bootloader and reflash OEM-signed firmware to restore green verified boot state."
                )
            elif signal == "flash_locked":
                hints.append(
                    "Re-lock flash via fastboot to prevent unauthorized firmware overwrites."
                )
            elif signal == "vbmeta_device_state":
                hints.append(
                    "Re-lock vbmeta device state to restore AVB enforcement across boot partitions."
                )
            elif signal == "dm_verity":
                hints.append(
                    "Re-enable dm-verity to restore runtime partition integrity verification."
                )
            elif signal == "secure_boot":
                hints.append(
                    "Investigate why secure boot reports disabled; this may indicate custom firmware or a provisioning defect."
                )

        if severity == "warning":
            if signal == "oem_unlock_allowed":
                hints.append(
                    "Disable OEM unlocking in Developer Options to prevent fastboot bootloader unlock."
                )
            if signal == "warranty_bit":
                hints.append(
                    "Warranty bit is permanently tripped on most devices; note this in forensic reporting."
                )

    if not hints:
        hints.append(
            "Boot chain configuration appears nominal; capture and preserve this baseline for comparison."
        )

    return hints[:6]
