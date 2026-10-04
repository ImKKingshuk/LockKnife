from __future__ import annotations

from unittest.mock import MagicMock

from lockknife.core.device import DeviceManager
from lockknife.modules.security.device_audit import run_device_audit


def test_device_audit_high_risk_posture_checks() -> None:
    dev = MagicMock(spec=DeviceManager)
    dev.has_root.return_value = True
    dev.info.return_value.props = {
        "ro.build.tags": "release-keys",
        "ro.build.selinux": "1",
        "ro.build.version.sdk": "34",
        "ro.build.version.security_patch": "2026-01-01",
        "ro.crypto.state": "encrypted",
    }

    def fake_shell(serial: str, cmd: str, timeout_s: float = 10.0) -> str:
        if "lockscreen.disabled" in cmd:
            return "1\n"
        if "lock_pattern_autolock" in cmd:
            return "0\n"
        if "gatekeeper" in cmd:
            return "/data/system/gatekeeper.password.key\n"
        if "http_proxy" in cmd:
            return "proxy.corp.internal:8080\n"
        if "private_dns_mode" in cmd:
            return "off\n"
        if "adb_wifi_enabled" in cmd:
            return "1\n"
        if "verifier_verify_adb_installs" in cmd:
            return "0\n"
        if "mock_location" in cmd:
            return "1\n"
        if "device_policy" in cmd:
            return "Active Admin: ComponentInfo{com.mdm.agent/com.mdm.Receiver}\n"
        return ""

    dev.shell.side_effect = fake_shell

    findings = run_device_audit(dev, "serial-audit")
    ids = {f.id: f for f in findings}

    assert "lockscreen_disabled" in ids
    assert ids["lockscreen_disabled"].severity == "high"

    assert "pattern_autolock_disabled" in ids
    assert ids["pattern_autolock_disabled"].severity == "medium"

    assert "credential_enrolled" in ids
    assert ids["credential_enrolled"].severity == "info"

    assert "http_proxy" in ids
    assert ids["http_proxy"].severity == "high"
    assert "proxy.corp.internal:8080" in ids["http_proxy"].details.get("http_proxy", "")

    assert "private_dns" in ids
    assert ids["private_dns"].severity == "medium"

    assert "adb_wifi" in ids
    assert ids["adb_wifi"].severity == "medium"

    assert "verify_adb_installs" in ids
    assert ids["verify_adb_installs"].severity == "medium"

    assert "mock_location" in ids
    assert ids["mock_location"].severity == "medium"

    assert "device_policy" in ids
    assert "com.mdm.agent" in ids["device_policy"].details.get("device_policy_summary", "")


def test_device_audit_secure_baseline() -> None:
    dev = MagicMock(spec=DeviceManager)
    dev.has_root.return_value = False
    dev.info.return_value.props = {
        "ro.build.tags": "release-keys",
        "ro.build.selinux": "1",
        "ro.build.version.sdk": "34",
        "ro.build.version.security_patch": "2026-09-01",
        "ro.crypto.state": "encrypted",
    }

    def fake_shell(serial: str, cmd: str, timeout_s: float = 10.0) -> str:
        if "lockscreen.disabled" in cmd:
            return "0\n"
        if "lock_pattern_autolock" in cmd:
            return "1\n"
        if "http_proxy" in cmd:
            return ":0\n"
        if "private_dns_mode" in cmd:
            return "hostname\n"
        if "private_dns_specifier" in cmd:
            return "dns.quad9.net\n"
        if "adb_wifi_enabled" in cmd:
            return "0\n"
        if "verifier_verify_adb_installs" in cmd:
            return "1\n"
        if "mock_location" in cmd:
            return "0\n"
        if "package_verifier_enable" in cmd:
            return "1\n"
        return ""

    dev.shell.side_effect = fake_shell

    findings = run_device_audit(dev, "serial-secure")
    ids = {f.id: f for f in findings}

    assert "lockscreen_disabled" not in ids
    assert "http_proxy" not in ids
    assert ids["private_dns"].severity == "info"
    assert ids["private_dns"].details.get("specifier") == "dns.quad9.net"
    assert "adb_wifi" not in ids
    assert "mock_location" not in ids
