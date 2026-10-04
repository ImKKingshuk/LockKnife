"""Tests for Batch 7 hardened modules: bootloader, hardware, network_scan, location."""

from __future__ import annotations

import dataclasses
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_device_manager(props: dict[str, str], shell_returns: dict[str, str] | None = None, has_root: bool = True) -> MagicMock:
    """Build a mocked DeviceManager returning *props* from info() and optional shell returns."""
    dm = MagicMock()
    info_obj = MagicMock()
    info_obj.props = props
    dm.info.return_value = info_obj
    dm.has_root.return_value = has_root

    def _shell(serial: str, cmd: str, timeout_s: float = 10.0) -> str:
        if shell_returns:
            for key, val in shell_returns.items():
                if key in cmd:
                    return val
        return ""

    dm.shell.side_effect = _shell
    return dm


# ===========================================================================
# security.bootloader
# ===========================================================================


class TestBootloaderHardening:
    """Tests for the hardened bootloader module."""

    def test_basic_property_extraction(self) -> None:
        from lockknife.modules.security.bootloader import analyze_bootloader

        props = {
            "ro.oem_unlock_supported": "1",
            "sys.oem_unlock_allowed": "0",
            "ro.boot.flash.locked": "1",
            "ro.boot.verifiedbootstate": "green",
            "ro.boot.vbmeta.device_state": "locked",
            "ro.boot.bootloader": "BL_v2.0",
            "ro.boot.slot_suffix": "_a",
            "ro.boot.warranty_bit": "0",
        }
        dm = _make_device_manager(props)
        status = analyze_bootloader(dm, "device1")
        assert status.serial == "device1"
        assert status.oem_unlock_supported == "1"
        assert status.oem_unlock_allowed == "0"
        assert status.flash_locked == "1"
        assert status.verifiedbootstate == "green"
        assert status.bootloader == "BL_v2.0"
        assert status.warranty_bit == "0"

    def test_avb_properties(self) -> None:
        from lockknife.modules.security.bootloader import analyze_bootloader

        props = {
            "ro.boot.avb_version": "1.2",
            "ro.boot.veritymode": "enforcing",
            "ro.boot.verifiedbootstate": "green",
            "ro.boot.vbmeta.hash_alg": "sha256",
            "ro.boot.vbmeta.digest": "abc123",
            "ro.boot.secureboot": "1",
            "ro.boot.vbmeta.security_patch_level": "2025-09-05",
        }
        dm = _make_device_manager(props)
        status = analyze_bootloader(dm, "device1")
        assert status.avb_version == "1.2"
        assert status.dm_verity_state == "enforcing"
        assert status.vbmeta_hash_alg == "sha256"
        assert status.vbmeta_digest == "abc123"
        assert status.secure_boot == "1"
        assert status.anti_rollback_index == "2025-09-05"

    def test_green_boot_low_risk(self) -> None:
        from lockknife.modules.security.bootloader import analyze_bootloader

        props = {
            "ro.boot.verifiedbootstate": "green",
            "sys.oem_unlock_allowed": "0",
            "ro.boot.flash.locked": "1",
            "ro.boot.vbmeta.device_state": "locked",
            "ro.boot.veritymode": "enforcing",
            "ro.boot.avb_version": "2.0",
            "ro.boot.secureboot": "1",
            "ro.boot.warranty_bit": "0",
        }
        dm = _make_device_manager(props)
        status = analyze_bootloader(dm, "device1")
        assert status.posture["risk_level"] == "low"
        assert status.posture["risk_score"] == 0

    def test_unlocked_bootloader_high_risk(self) -> None:
        from lockknife.modules.security.bootloader import analyze_bootloader

        props = {
            "ro.boot.verifiedbootstate": "orange",
            "sys.oem_unlock_allowed": "1",
            "ro.boot.flash.locked": "0",
            "ro.boot.vbmeta.device_state": "unlocked",
            "ro.boot.veritymode": "disabled",
            "ro.boot.secureboot": "0",
            "ro.boot.warranty_bit": "1",
        }
        dm = _make_device_manager(props)
        status = analyze_bootloader(dm, "device1")
        assert status.posture["risk_level"] in {"critical", "high"}
        assert status.posture["risk_score"] >= 8
        assert len(status.remediation_hints) > 0

    def test_remediation_hints_present(self) -> None:
        from lockknife.modules.security.bootloader import analyze_bootloader

        props = {"ro.boot.verifiedbootstate": "orange", "ro.boot.flash.locked": "0"}
        dm = _make_device_manager(props)
        status = analyze_bootloader(dm, "device1")
        assert len(status.remediation_hints) >= 1
        assert any("lock" in h.lower() or "re-lock" in h.lower() for h in status.remediation_hints)

    def test_red_boot_state_critical(self) -> None:
        from lockknife.modules.security.bootloader import analyze_bootloader

        props = {"ro.boot.verifiedbootstate": "red"}
        dm = _make_device_manager(props)
        status = analyze_bootloader(dm, "device1")
        findings = status.posture.get("findings", [])
        red_findings = [f for f in findings if f.get("value") == "red"]
        assert len(red_findings) == 1
        assert red_findings[0]["severity"] == "critical"


# ===========================================================================
# security.hardware
# ===========================================================================


class TestHardwareHardening:
    """Tests for the hardened hardware security module."""

    def test_basic_property_extraction(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {
            "ro.hardware.keystore": "trusty",
            "ro.hardware.keymaster": "trusty",
            "ro.hardware.gatekeeper": "trusty",
            "ro.hardware.fingerprint": "goodix",
            "ro.hardware.biometrics.face": "vendor_face",
        }
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.keystore_hw == "trusty"
        assert status.keymaster_hw == "trusty"
        assert status.gatekeeper_hw == "trusty"
        assert status.fingerprint_hw == "goodix"
        assert status.face_hw == "vendor_face"

    def test_tee_detection_trusty(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {"ro.hardware.keymaster": "trusty"}
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.tee_type == "Trusty"
        assert status.tee_vendor == "Google/ARM"

    def test_tee_detection_qsee(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {"ro.hardware.keystore": "qcom"}
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.tee_type == "QSEE"
        assert status.tee_vendor == "Qualcomm"

    def test_tee_detection_samsung(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {"ro.hardware.keymaster": "samsung_teegris"}
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.tee_type == "TEEGRIS"
        assert status.tee_vendor == "Samsung"

    def test_strongbox_detection(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {"ro.hardware.strongbox_keystore": "yes", "ro.build.version.sdk": "30"}
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.strongbox is True

    def test_attestation_capable_api30(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {
            "ro.hardware.keystore": "trusty",
            "ro.build.version.sdk": "30",
        }
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.attestation_capable is True

    def test_attestation_not_capable_api25(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {
            "ro.hardware.keystore": "trusty",
            "ro.build.version.sdk": "25",
        }
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.attestation_capable is False

    def test_biometric_class_fingerprint(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {"ro.hardware.fingerprint": "goodix"}
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.biometric_class == "class-3"

    def test_biometric_class_face_only(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {"ro.hardware.biometrics.face": "vendor_face"}
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.biometric_class == "class-2"

    def test_security_patch_current(self) -> None:
        import datetime
        from lockknife.modules.security.hardware import analyze_hardware_security

        today = datetime.date.today()
        recent = f"{today.year}-{today.month:02d}-01"
        props = {
            "ro.build.version.security_patch": recent,
            "ro.hardware.keystore": "trusty",
            "ro.build.version.sdk": "30",
        }
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        # Should detect current patch
        patch_findings = [f for f in status.posture.get("findings", []) if f.get("signal") == "security_patch"]
        assert len(patch_findings) == 1
        assert "current" in patch_findings[0]["detail"]

    def test_security_patch_outdated(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {
            "ro.build.version.security_patch": "2020-01-01",
            "ro.hardware.keystore": "trusty",
            "ro.build.version.sdk": "30",
        }
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        patch_findings = [f for f in status.posture.get("findings", []) if f.get("signal") == "security_patch"]
        assert len(patch_findings) == 1
        assert "outdated" in patch_findings[0]["detail"]

    def test_encryption_state(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {"ro.crypto.state": "encrypted", "ro.crypto.type": "file"}
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.crypto_state == "encrypted"
        assert status.disk_encryption == "file"

    def test_posture_low_risk_full_hw(self) -> None:
        import datetime
        from lockknife.modules.security.hardware import analyze_hardware_security

        today = datetime.date.today()
        props = {
            "ro.hardware.keystore": "trusty",
            "ro.hardware.keymaster": "trusty",
            "ro.hardware.gatekeeper": "trusty",
            "ro.hardware.fingerprint": "goodix",
            "ro.build.version.sdk": "34",
            "ro.build.version.security_patch": f"{today.year}-{today.month:02d}-01",
            "ro.crypto.state": "encrypted",
        }
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.posture["risk_level"] == "low"

    def test_posture_high_risk_no_hw(self) -> None:
        from lockknife.modules.security.hardware import analyze_hardware_security

        props = {"ro.build.version.security_patch": "2020-01-01"}
        dm = _make_device_manager(props)
        status = analyze_hardware_security(dm, "device1")
        assert status.posture["risk_level"] in {"high", "medium"}
        assert len(status.remediation_hints) >= 1


# ===========================================================================
# security.network_scan
# ===========================================================================


class TestNetworkScanHardening:
    """Tests for the hardened network scan module."""

    def test_parse_listening_ports(self) -> None:
        from lockknife.modules.security.network_scan import _parse_listening_ports

        raw = (
            "tcp        0      0 0.0.0.0:5555            0.0.0.0:*               LISTEN      123/adbd\n"
            "tcp6       0      0 :::443                  :::*                    LISTEN      456/nginx\n"
            "udp        0      0 0.0.0.0:53              0.0.0.0:*                           789/dnsmasq\n"
        )
        ports = _parse_listening_ports(raw)
        assert len(ports) == 3
        assert ports[0].port == 5555
        assert ports[0].service_name == "ADB-TCP"
        assert ports[0].risk_level == "high"
        assert ports[1].port == 443
        assert ports[1].service_name == "HTTPS"
        assert ports[1].risk_level == "low"
        assert ports[2].port == 53
        assert ports[2].service_name == "DNS"

    def test_classify_critical_port(self) -> None:
        from lockknife.modules.security.network_scan import _classify_port

        name, risk, note = _classify_port(4444)
        assert risk == "critical"
        assert name == "Metasploit"

    def test_classify_unknown_port(self) -> None:
        from lockknife.modules.security.network_scan import _classify_port

        name, risk, note = _classify_port(12345)
        assert risk == "info"

    def test_classify_privileged_unknown(self) -> None:
        from lockknife.modules.security.network_scan import _classify_port

        name, risk, note = _classify_port(999)
        assert risk == "medium"

    def test_classify_ephemeral(self) -> None:
        from lockknife.modules.security.network_scan import _classify_port

        name, risk, note = _classify_port(50000)
        assert risk == "low"

    def test_extract_port(self) -> None:
        from lockknife.modules.security.network_scan import _extract_port

        assert _extract_port("0.0.0.0:5555") == 5555
        assert _extract_port(":::443") == 443
        assert _extract_port("127.0.0.1:8080") == 8080
        assert _extract_port("some_garbage") is None

    def test_posture_critical_with_backdoor_port(self) -> None:
        from lockknife.modules.security.network_scan import _parse_listening_ports, _assess_network_posture

        raw = "tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      666/revshell\n"
        ports = _parse_listening_ports(raw)
        posture = _assess_network_posture(
            listening=ports, vpn_active=False, tethering_active=False, iptables_rules=[], dns=[]
        )
        assert posture["risk_level"] in {"critical", "high"}

    def test_posture_low_with_no_ports(self) -> None:
        from lockknife.modules.security.network_scan import _assess_network_posture

        posture = _assess_network_posture(
            listening=[], vpn_active=False, tethering_active=False, iptables_rules=[], dns=[]
        )
        assert posture["risk_level"] == "low"

    def test_scan_requires_root(self) -> None:
        from lockknife.modules.security.network_scan import scan_network
        from lockknife.core.exceptions import DeviceError

        dm = _make_device_manager({}, has_root=False)
        with pytest.raises(DeviceError, match="Root required"):
            scan_network(dm, "device1")

    def test_remediation_hints_adb_tcp(self) -> None:
        from lockknife.modules.security.network_scan import _parse_listening_ports, _assess_network_posture, _network_remediation_hints

        raw = "tcp        0      0 0.0.0.0:5555            0.0.0.0:*               LISTEN      123/adbd\n"
        ports = _parse_listening_ports(raw)
        posture = _assess_network_posture(
            listening=ports, vpn_active=False, tethering_active=False, iptables_rules=[], dns=[]
        )
        hints = _network_remediation_hints(posture)
        assert any("ADB" in h or "adb" in h for h in hints)


# ===========================================================================
# extraction.location
# ===========================================================================


class TestLocationHardening:
    """Tests for the hardened location extraction module."""

    def test_location_settings_high_accuracy(self) -> None:
        from lockknife.modules.extraction.location import _extract_location_settings

        shell_returns = {
            "location_mode": "3",
            "location_providers_allowed": "gps,network",
            "mock_location": "0",
        }
        dm = _make_device_manager({}, shell_returns=shell_returns)
        settings = _extract_location_settings(dm, "device1")
        assert settings.location_mode == "high_accuracy"
        assert settings.high_accuracy is True
        assert settings.gps_enabled is True
        assert settings.network_enabled is True

    def test_location_settings_off(self) -> None:
        from lockknife.modules.extraction.location import _extract_location_settings

        shell_returns = {"location_mode": "0", "location_providers_allowed": ""}
        dm = _make_device_manager({}, shell_returns=shell_returns)
        settings = _extract_location_settings(dm, "device1")
        assert settings.location_mode == "off"
        assert settings.high_accuracy is False

    def test_gnss_parsing(self) -> None:
        from lockknife.modules.extraction.location import _extract_gnss_status

        gnss_raw = (
            "gnss_provider:\n"
            "  num_svs=12\n"
            "  fix_type=1\n"
            "  GPS GLONASS GALILEO\n"
        )
        shell_returns = {"gnss": gnss_raw}
        dm = _make_device_manager({}, shell_returns=shell_returns)
        gnss = _extract_gnss_status(dm, "device1")
        assert gnss.satellite_count == 12
        assert gnss.fix_type == "gps"
        assert "GALILEO" in gnss.constellations
        assert "GPS" in gnss.constellations

    def test_cell_tower_parsing_lte(self) -> None:
        from lockknife.modules.extraction.location import _parse_cell_towers

        raw = "CellIdentityLte{ mMcc=310 mMnc=260 mTac=123 mEci=456789 mPci=42 }"
        towers = _parse_cell_towers(raw)
        assert len(towers) == 1
        assert towers[0].kind == "lte"
        assert towers[0].mcc == 310
        assert towers[0].mnc == 260
        assert towers[0].tac == 123
        assert towers[0].pci == 42

    def test_cell_tower_parsing_nr(self) -> None:
        from lockknife.modules.extraction.location import _parse_cell_towers

        raw = "CellIdentityNr{ mMcc=460 mMnc=11 mPci=100 mTac=200 }"
        towers = _parse_cell_towers(raw)
        assert len(towers) == 1
        assert towers[0].kind == "nr"

    def test_wifi_ap_parsing(self) -> None:
        from lockknife.modules.extraction.location import _parse_wifi_scan

        raw = "SSID: TestNetwork, BSSID: aa:bb:cc:dd:ee:ff, level: -65, frequency: 2437"
        aps = _parse_wifi_scan(raw)
        assert len(aps) == 1
        assert aps[0].ssid == "TestNetwork"
        assert aps[0].bssid == "aa:bb:cc:dd:ee:ff"
        assert aps[0].level == -65
        assert aps[0].frequency == 2437

    def test_location_snapshot_parsing(self) -> None:
        from lockknife.modules.extraction.location import extract_location_snapshot

        loc_raw = "provider=gps lat=37.7749 lon=-122.4194"
        shell_returns = {"dumpsys location": loc_raw}
        dm = _make_device_manager({}, shell_returns=shell_returns)
        snap = extract_location_snapshot(dm, "device1")
        assert snap.provider == "gps"
        assert snap.latitude == pytest.approx(37.7749)
        assert snap.longitude == pytest.approx(-122.4194)

    def test_posture_rich_data(self) -> None:
        from lockknife.modules.extraction.location import (
            _assess_location_posture,
            LocationSettings,
            GnssStatus,
        )

        settings = LocationSettings(
            location_mode="high_accuracy", high_accuracy=True,
            gps_enabled=True, network_enabled=True,
        )
        gnss = GnssStatus(satellite_count=10, constellations=["GPS", "GLONASS"])
        posture = _assess_location_posture(settings, gnss, history_count=25, wifi_count=10, cell_count=3)
        assert posture["data_richness"] == "rich"
        assert posture["data_source_count"] >= 2

    def test_posture_limited_data(self) -> None:
        from lockknife.modules.extraction.location import (
            _assess_location_posture,
            LocationSettings,
            GnssStatus,
        )

        settings = LocationSettings(location_mode="off")
        gnss = GnssStatus()
        posture = _assess_location_posture(settings, gnss, history_count=0, wifi_count=0, cell_count=0)
        assert posture["data_richness"] == "limited"

    def test_mock_location_warning(self) -> None:
        from lockknife.modules.extraction.location import (
            _assess_location_posture,
            LocationSettings,
            GnssStatus,
        )

        settings = LocationSettings(mock_location="com.example.mockgps")
        gnss = GnssStatus()
        posture = _assess_location_posture(settings, gnss, history_count=0, wifi_count=0, cell_count=0)
        mock_findings = [f for f in posture.get("findings", []) if f.get("signal") == "mock_location"]
        assert len(mock_findings) == 1
        assert mock_findings[0]["severity"] == "warning"

    def test_location_history_e7_conversion(self) -> None:
        """Verify E7 integer lat/lon is converted to decimal degrees."""
        from lockknife.modules.extraction.location import _extract_location_history

        # Simulate shell that returns E7-formatted lat/lon
        history_raw = "1696500000|377749000|-1224194000|25|gps"
        shell_returns = {"sqlite3": history_raw}
        dm = _make_device_manager({}, shell_returns=shell_returns)
        entries = _extract_location_history(dm, "device1")
        assert len(entries) == 1
        assert entries[0].latitude == pytest.approx(37.7749, rel=1e-3)
        assert entries[0].longitude == pytest.approx(-122.4194, rel=1e-3)

    def test_provider_summary_structure(self) -> None:
        from lockknife.modules.extraction.location import (
            _build_provider_summary,
            LocationSettings,
            GnssStatus,
        )

        settings = LocationSettings(gps_enabled=True, network_enabled=True)
        gnss = GnssStatus(satellite_count=8, constellations=["GPS"])
        summary = _build_provider_summary("fused provider active", settings, gnss)
        assert summary["provider_count"] >= 2
        assert summary["high_accuracy"] is False  # not mode=3 but both enabled
        names = [p["name"] for p in summary["providers"]]
        assert "gps" in names
        assert "network" in names
        assert "fused" in names
