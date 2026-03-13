from __future__ import annotations

import dataclasses
import datetime
from typing import Any

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger

log = get_logger()


@dataclasses.dataclass(frozen=True)
class AuditFinding:
    """Single security-relevant device audit finding."""

    id: str
    severity: str
    title: str
    details: dict[str, str]


def _shell_best_effort(devices: DeviceManager, serial: str, command: str, *, timeout_s: float = 10.0) -> str | None:
    try:
        return devices.shell(serial, command, timeout_s=timeout_s).strip()
    except Exception:
        log.debug("device_audit_shell_failed", exc_info=True, serial=serial, command=command)
        return None


def _parse_security_patch(v: str | None) -> datetime.date | None:
    if not v:
        return None
    s = v.strip()
    try:
        return datetime.date.fromisoformat(s)
    except Exception:
        return None


def run_device_audit(devices: DeviceManager, serial: str) -> list[AuditFinding]:
    """Run a best-effort security audit on a connected Android device.

    The audit is non-destructive and relies on system properties and adb shell
    queries to surface high-signal configuration and security posture checks.
    """
    props = devices.info(serial).props
    findings: list[AuditFinding] = []

    tags = props.get("ro.build.tags", "")
    if "test-keys" in tags:
        findings.append(AuditFinding(id="test_keys", severity="medium", title="Build signed with test-keys", details={"ro.build.tags": tags}))

    selinux = props.get("ro.build.selinux", "")
    if selinux and selinux.lower() not in {"1", "true"}:
        findings.append(AuditFinding(id="selinux_flag", severity="low", title="SELinux flag unusual", details={"ro.build.selinux": selinux}))

    sdk = props.get("ro.build.version.sdk", "")
    if sdk:
        findings.append(AuditFinding(id="sdk", severity="info", title="Android SDK level", details={"ro.build.version.sdk": sdk}))

    patch_raw = props.get("ro.build.version.security_patch", "")
    if patch_raw:
        patch = _parse_security_patch(patch_raw)
        sev = "info"
        if patch:
            age_days = (datetime.date.today() - patch).days
            if age_days > 365:
                sev = "high"
            elif age_days > 180:
                sev = "medium"
        findings.append(
            AuditFinding(
                id="security_patch",
                severity=sev,
                title="Android security patch level",
                details={"ro.build.version.security_patch": patch_raw},
            )
        )

    crypto_state = props.get("ro.crypto.state") or props.get("ro.crypto.type") or ""
    if crypto_state:
        lowered = crypto_state.strip().lower()
        if lowered in {"unencrypted", "unsupported", "none"}:
            findings.append(AuditFinding(id="encryption", severity="high", title="Device encryption disabled", details={"ro.crypto.state": crypto_state}))
        else:
            findings.append(AuditFinding(id="encryption", severity="info", title="Device encryption state", details={"ro.crypto.state": crypto_state}))

    adb_enabled = _shell_best_effort(devices, serial, "settings get global adb_enabled 2>/dev/null || echo ''")
    if adb_enabled:
        sev = "medium" if adb_enabled.strip() == "1" else "info"
        findings.append(AuditFinding(id="adb_debug", severity=sev, title="ADB debugging setting", details={"adb_enabled": adb_enabled}))

    dev_opts = _shell_best_effort(devices, serial, "settings get global development_settings_enabled 2>/dev/null || echo ''")
    if dev_opts:
        sev = "low" if dev_opts.strip() == "1" else "info"
        findings.append(
            AuditFinding(
                id="developer_options",
                severity=sev,
                title="Developer options",
                details={"development_settings_enabled": dev_opts},
            )
        )

    unknown_sources = _shell_best_effort(devices, serial, "settings get secure install_non_market_apps 2>/dev/null || echo ''")
    if unknown_sources:
        sev = "medium" if unknown_sources.strip() == "1" else "info"
        findings.append(
            AuditFinding(
                id="unknown_sources",
                severity=sev,
                title="Unknown sources install setting",
                details={"install_non_market_apps": unknown_sources},
            )
        )

    verifier_enabled = _shell_best_effort(devices, serial, "settings get global package_verifier_enable 2>/dev/null || echo ''")
    if verifier_enabled:
        sev = "medium" if verifier_enabled.strip() in {"0", "false"} else "info"
        findings.append(
            AuditFinding(
                id="play_protect",
                severity=sev,
                title="Package verifier (Play Protect) setting",
                details={"package_verifier_enable": verifier_enabled},
            )
        )

    if devices.has_root(serial):
        findings.append(AuditFinding(id="root", severity="info", title="su binary present", details={}))
    else:
        findings.append(AuditFinding(id="no_root", severity="info", title="No su detected", details={}))

    return findings
