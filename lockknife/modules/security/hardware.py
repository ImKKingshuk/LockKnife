from __future__ import annotations

import dataclasses
import re
from typing import Any

from lockknife.core.device import DeviceManager
from lockknife.core.logging import get_logger

log = get_logger()


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
    # --- Batch 7: TEE, attestation, biometric, patch posture ---
    tee_type: str | None = None
    tee_vendor: str | None = None
    attestation_capable: bool = False
    keystore_version: str | None = None
    keymaster_version: str | None = None
    iris_hw: str | None = None
    biometric_class: str | None = None
    security_patch: str | None = None
    vendor_patch: str | None = None
    boot_patch: str | None = None
    first_api_level: str | None = None
    crypto_state: str | None = None
    disk_encryption: str | None = None
    posture: dict[str, Any] = dataclasses.field(default_factory=dict)
    remediation_hints: list[str] = dataclasses.field(default_factory=list)


def analyze_hardware_security(devices: DeviceManager, serial: str) -> HardwareSecurityStatus:
    props = devices.info(serial).props

    # --- Keystore / Keymaster / Gatekeeper ---
    ks = props.get("ro.hardware.keystore") or props.get("ro.hardware.keystore_des")
    km = props.get("ro.hardware.keymaster") or props.get("ro.hardware.keymaster_hal")
    gk = props.get("ro.hardware.gatekeeper")

    # --- StrongBox detection ---
    strongbox = False
    for k, v in props.items():
        if "strongbox" in k.lower() or "strongbox" in (v or "").lower():
            strongbox = True
            break

    # --- Biometrics ---
    fp = props.get("ro.hardware.fingerprint") or props.get("ro.hardware.biometrics.fingerprint")
    face = props.get("ro.hardware.biometrics.face")
    iris = props.get("ro.hardware.biometrics.iris")

    # --- Samsung Knox ---
    knox = (
        props.get("ro.config.knox")
        or props.get("ro.vendor.knox.version")
        or props.get("ro.boot.knox")
    )

    # --- TEE detection ---
    tee_type, tee_vendor = _detect_tee(props)

    # --- Attestation ---
    attestation_capable = _detect_attestation(props, ks, km)

    # --- Version info ---
    keystore_version = props.get("ro.hardware.keystore.version")
    keymaster_version = (
        props.get("ro.hardware.keymaster.version")
        or props.get("ro.hardware.keymaster_hal.version")
    )

    # --- Biometric class ---
    biometric_class = _assess_biometric_class(fp, face, iris, strongbox)

    # --- Security patch levels ---
    security_patch = props.get("ro.build.version.security_patch")
    vendor_patch = props.get("ro.vendor.build.security_patch")
    boot_patch = props.get("ro.boot.vbmeta.security_patch_level")
    first_api_level = props.get("ro.product.first_api_level")

    # --- Encryption ---
    crypto_state = props.get("ro.crypto.state")
    disk_encryption = (
        props.get("ro.crypto.type")
        or props.get("ro.crypto.fs_type")
    )

    posture = _assess_hardware_posture(
        ks=ks, km=km, gk=gk, strongbox=strongbox,
        tee_type=tee_type, tee_vendor=tee_vendor,
        attestation_capable=attestation_capable,
        biometric_class=biometric_class,
        security_patch=security_patch,
        vendor_patch=vendor_patch,
        crypto_state=crypto_state,
        knox=knox,
    )
    remediation_hints = _hardware_remediation_hints(posture)

    return HardwareSecurityStatus(
        serial=serial,
        keystore_hw=ks,
        keymaster_hw=km,
        gatekeeper_hw=gk,
        strongbox=strongbox,
        fingerprint_hw=fp,
        face_hw=face,
        knox=knox,
        tee_type=tee_type,
        tee_vendor=tee_vendor,
        attestation_capable=attestation_capable,
        keystore_version=keystore_version,
        keymaster_version=keymaster_version,
        iris_hw=iris,
        biometric_class=biometric_class,
        security_patch=security_patch,
        vendor_patch=vendor_patch,
        boot_patch=boot_patch,
        first_api_level=first_api_level,
        crypto_state=crypto_state,
        disk_encryption=disk_encryption,
        posture=posture,
        remediation_hints=remediation_hints,
    )


def _detect_tee(props: dict[str, str]) -> tuple[str | None, str | None]:
    """Detect the TEE implementation type and vendor from system properties."""
    tee_type: str | None = None
    tee_vendor: str | None = None

    # Direct TEE properties
    tee_prop = props.get("ro.hardware.tee") or props.get("ro.tee.type")
    if tee_prop:
        tee_type = tee_prop.strip()

    # Infer from keymaster/keystore HAL names
    hal_clues = (
        (props.get("ro.hardware.keymaster") or "")
        + " "
        + (props.get("ro.hardware.keystore") or "")
        + " "
        + (props.get("ro.hardware.gatekeeper") or "")
    ).lower()

    if "trusty" in hal_clues or "trusty" in (tee_type or "").lower():
        tee_type = tee_type or "Trusty"
        tee_vendor = "Google/ARM"
    elif "qsee" in hal_clues or "qcom" in hal_clues or "qualcomm" in hal_clues:
        tee_type = tee_type or "QSEE"
        tee_vendor = "Qualcomm"
    elif "teegris" in hal_clues or "samsung" in hal_clues:
        tee_type = tee_type or "TEEGRIS"
        tee_vendor = "Samsung"
    elif "kinibi" in hal_clues or "mobicore" in hal_clues:
        tee_type = tee_type or "Kinibi"
        tee_vendor = "Trustonic"
    elif "mtk" in hal_clues or "mediatek" in hal_clues:
        tee_type = tee_type or "Microtrust/ISEE"
        tee_vendor = "MediaTek"
    elif "beanpod" in hal_clues or "isee" in hal_clues:
        tee_type = tee_type or "ISEE"
        tee_vendor = "Beanpod"
    elif "huawei" in hal_clues or "iTrustee" in hal_clues:
        tee_type = tee_type or "iTrustee"
        tee_vendor = "Huawei"

    # Fallback: check broader property space
    if not tee_vendor:
        for k, v in props.items():
            combined = (k + " " + (v or "")).lower()
            if "trusty" in combined:
                tee_type = tee_type or "Trusty"
                tee_vendor = "Google/ARM"
                break
            if "qsee" in combined or "qualcomm" in combined:
                tee_type = tee_type or "QSEE"
                tee_vendor = "Qualcomm"
                break
            if "teegris" in combined:
                tee_type = tee_type or "TEEGRIS"
                tee_vendor = "Samsung"
                break

    return tee_type, tee_vendor


def _detect_attestation(
    props: dict[str, str], ks: str | None, km: str | None
) -> bool:
    """Heuristically determine if the device supports hardware key attestation."""
    # Devices with hardware keystore/keymaster on API >= 26 generally support attestation
    api_level_str = props.get("ro.build.version.sdk") or "0"
    try:
        api_level = int(api_level_str)
    except ValueError:
        api_level = 0

    if api_level < 26:
        return False

    # Must have some hardware-backed keystore or keymaster
    has_hw = bool(ks or km)
    if not has_hw:
        return False

    # StrongBox or known TEE keymaster/keystore is strong evidence
    for k, v in props.items():
        combined = (k + " " + (v or "")).lower()
        if "strongbox" in combined:
            return True
        if any(t in combined for t in ("trusty", "qsee", "teegris", "kinibi")):
            return True

    # API >= 26 + hardware keymaster is sufficient
    return True


def _assess_biometric_class(
    fp: str | None, face: str | None, iris: str | None, strongbox: bool
) -> str | None:
    """Classify the biometric security tier based on available sensors."""
    sensors = []
    if fp:
        sensors.append("fingerprint")
    if face:
        sensors.append("face")
    if iris:
        sensors.append("iris")

    if not sensors:
        return None

    # Iris + StrongBox = Class 3 (highest)
    # Fingerprint on most modern devices = Class 3
    # Face without depth sensor typically = Class 2 or lower
    if iris or (fp and strongbox):
        return "class-3"
    if fp:
        return "class-3"
    if face:
        return "class-2"
    return "class-1"


def _assess_hardware_posture(
    *,
    ks: str | None,
    km: str | None,
    gk: str | None,
    strongbox: bool,
    tee_type: str | None,
    tee_vendor: str | None,
    attestation_capable: bool,
    biometric_class: str | None,
    security_patch: str | None,
    vendor_patch: str | None,
    crypto_state: str | None,
    knox: str | None,
) -> dict[str, Any]:
    """Derive a composite hardware security posture with risk scoring."""
    findings: list[dict[str, str]] = []
    risk_score = 0

    # --- Keystore/Keymaster ---
    if ks or km:
        findings.append({"signal": "hw_keystore", "value": ks or km or "present",
                         "severity": "ok",
                         "detail": "Hardware-backed keystore/keymaster is available for key operations."})
    else:
        findings.append({"signal": "hw_keystore", "value": "absent", "severity": "high",
                         "detail": "No hardware-backed keystore detected; keys may use software-only storage."})
        risk_score += 3

    # --- Gatekeeper ---
    if gk:
        findings.append({"signal": "hw_gatekeeper", "value": gk, "severity": "ok",
                         "detail": "Hardware-backed gatekeeper is present for credential verification throttling."})
    else:
        findings.append({"signal": "hw_gatekeeper", "value": "absent", "severity": "warning",
                         "detail": "No hardware gatekeeper detected; credential throttling may be software-only."})
        risk_score += 1

    # --- StrongBox ---
    if strongbox:
        findings.append({"signal": "strongbox", "value": "present", "severity": "ok",
                         "detail": "StrongBox secure element provides tamper-resistant key storage."})
    else:
        findings.append({"signal": "strongbox", "value": "absent", "severity": "info",
                         "detail": "No StrongBox detected; TEE-level key protection is the ceiling."})

    # --- TEE ---
    if tee_type:
        findings.append({"signal": "tee_type", "value": f"{tee_type} ({tee_vendor or 'unknown'})",
                         "severity": "ok",
                         "detail": f"Trusted Execution Environment: {tee_type} from {tee_vendor or 'unknown vendor'}."})
    else:
        findings.append({"signal": "tee_type", "value": "undetected", "severity": "warning",
                         "detail": "TEE type could not be determined from system properties."})
        risk_score += 1

    # --- Attestation ---
    if attestation_capable:
        findings.append({"signal": "attestation", "value": "capable", "severity": "ok",
                         "detail": "Device supports hardware key attestation (API 26+, HW keymaster)."})
    else:
        findings.append({"signal": "attestation", "value": "not detected", "severity": "warning",
                         "detail": "Hardware attestation capability not confirmed; may be absent or pre-API 26."})
        risk_score += 1

    # --- Biometric class ---
    if biometric_class:
        sev = "ok" if biometric_class == "class-3" else "info"
        findings.append({"signal": "biometric_class", "value": biometric_class, "severity": sev,
                         "detail": f"Biometric authentication classified as {biometric_class}."})
    else:
        findings.append({"signal": "biometric_class", "value": "none", "severity": "info",
                         "detail": "No biometric hardware detected in system properties."})

    # --- Security patch freshness ---
    if security_patch:
        freshness = _patch_freshness(security_patch)
        sev = "ok" if freshness == "current" else ("warning" if freshness == "stale" else "high")
        findings.append({"signal": "security_patch", "value": security_patch, "severity": sev,
                         "detail": f"Security patch level: {security_patch} ({freshness})."})
        if freshness == "outdated":
            risk_score += 3
        elif freshness == "stale":
            risk_score += 1
    else:
        findings.append({"signal": "security_patch", "value": "unknown", "severity": "warning",
                         "detail": "Security patch level could not be determined."})
        risk_score += 1

    # --- Encryption ---
    cs = (crypto_state or "").lower().strip()
    if cs == "encrypted":
        findings.append({"signal": "encryption", "value": "encrypted", "severity": "ok",
                         "detail": "Device storage reports encrypted state."})
    elif cs:
        findings.append({"signal": "encryption", "value": cs, "severity": "warning",
                         "detail": f"Device encryption state: {cs}."})
        risk_score += 2
    else:
        findings.append({"signal": "encryption", "value": "unknown", "severity": "info",
                         "detail": "Encryption state not reported in system properties."})

    # --- Knox ---
    if knox:
        findings.append({"signal": "knox", "value": knox, "severity": "ok",
                         "detail": f"Samsung Knox platform version: {knox}."})

    # --- Overall ---
    if risk_score >= 6:
        risk_level = "high"
        assessment = "Hardware security posture is materially weakened; key protection and credential security may not meet production standards."
    elif risk_score >= 3:
        risk_level = "medium"
        assessment = "Some hardware security gaps detected; review findings for impact on investigation integrity."
    else:
        risk_level = "low"
        assessment = "Hardware security posture is strong with hardware-backed key protection and current patch levels."

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "assessment": assessment,
        "findings": findings,
        "finding_count": len(findings),
    }


_RE_PATCH_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")


def _patch_freshness(patch_level: str) -> str:
    """Classify patch level freshness as current, stale, or outdated."""
    m = _RE_PATCH_DATE.match((patch_level or "").strip())
    if not m:
        return "unknown"

    import datetime

    try:
        patch_date = datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return "unknown"

    today = datetime.date.today()
    delta_days = (today - patch_date).days

    if delta_days <= 90:
        return "current"
    if delta_days <= 180:
        return "stale"
    return "outdated"


def _hardware_remediation_hints(posture: dict[str, Any]) -> list[str]:
    """Generate actionable remediation hints based on hardware posture."""
    hints: list[str] = []
    findings = posture.get("findings") or []

    for f in findings:
        severity = f.get("severity", "")
        signal = f.get("signal", "")

        if severity == "high":
            if signal == "hw_keystore":
                hints.append(
                    "Investigate why hardware keystore is absent; software-only keys are vulnerable to extraction from rooted devices."
                )
            if signal == "security_patch":
                hints.append(
                    "Update the device to the latest security patch level; outdated patches leave known vulnerabilities unpatched."
                )
            if signal == "encryption":
                hints.append(
                    "Enable full-disk or file-based encryption to protect data at rest from physical extraction."
                )

        if severity == "warning":
            if signal == "hw_gatekeeper":
                hints.append(
                    "Software-only gatekeeper may not enforce hardware-rate-limited credential verification."
                )
            if signal == "tee_type":
                hints.append(
                    "TEE detection failure may indicate an emulator, custom ROM, or stripped vendor partition."
                )

    if not hints:
        hints.append(
            "Hardware security posture appears strong; preserve this assessment as a forensic baseline."
        )

    return hints[:6]
