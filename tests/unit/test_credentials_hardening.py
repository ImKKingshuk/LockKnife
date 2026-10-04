from __future__ import annotations

import pathlib

import pytest

from lockknife.core.exceptions import DeviceError
from lockknife.modules.credentials._keystore_inventory import KEYSTORE_CANDIDATE_PATHS
from lockknife.modules.credentials._wifi_parse import parse_wifi_config_store_xml
from lockknife.modules.credentials.gesture import GestureKeyNotFound, pull_gesture_key
from lockknife.modules.credentials.pin import (
    _detect_synthetic_password,
    pull_locksettings_db,
    pull_password_key,
)
from lockknife.modules.credentials.wifi import extract_wifi_passwords


class _MockDevicesWithFallback:
    """Simulates an Android 12-15 device where direct adb pull is rejected for

    privileged paths (/data/system, /data/misc), requiring su root staging.
    """

    def __init__(self, remote_files: dict[str, bytes], has_root_flag: bool = True, spblob_present: bool = False) -> None:
        self.remote_files = remote_files
        self.has_root_flag = has_root_flag
        self.spblob_present = spblob_present
        self.shell_calls: list[str] = []
        self.pulled: list[tuple[str, str]] = []
        self._staged_files: dict[str, bytes] = {}

    def has_root(self, serial: str) -> bool:
        return self.has_root_flag

    def pull(self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 60.0) -> None:
        self.pulled.append((serial, remote_path))
        # If pulling directly from /data, simulate permission denied
        if remote_path.startswith("/data/"):
            raise PermissionError(f"adb: error: failed to copy '{remote_path}' to '{local_path}': Permission denied")

        # Pulling from staging path /sdcard/...
        if remote_path in self._staged_files:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(self._staged_files[remote_path])
            return

        raise FileNotFoundError(f"Remote file not found: {remote_path}")

    def shell(self, serial: str, command: str, timeout_s: float = 60.0) -> str:
        self.shell_calls.append(command)

        if "spblob" in command:
            if self.spblob_present:
                return "0000000000000000.spblob\nspblob_metadata\n"
            return ""

        if "cp " in command and "/sdcard/lockknife-staging-" in command:
            # Parse source and dest from command
            # Command format: su -c "cp '/data/...' '/sdcard/...' 2>/dev/null || cat ..."
            for remote_path, content in self.remote_files.items():
                if remote_path in command:
                    # Find staging target
                    import re
                    m = re.search(r"(/sdcard/lockknife-staging-[^\s'\"]+)", command)
                    if m:
                        staging_path = m.group(1)
                        self._staged_files[staging_path] = content
                        return ""
            return ""

        if "rm -f /sdcard/lockknife-staging-" in command:
            import re
            m = re.search(r"(/sdcard/lockknife-staging-[^\s'\"]+)", command)
            if m and m.group(1) in self._staged_files:
                del self._staged_files[m.group(1)]
            return ""

        return ""


def test_parse_modern_wifi_config_store_xml(tmp_path: pathlib.Path) -> None:
    xml_content = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<WifiConfigStoreData>
  <int name="Version" value="3" />
  <NetworkList>
    <Network>
      <WifiConfiguration>
        <string name="ConfigKey">&quot;Corp_Secure&quot;WPA_EAP</string>
        <string name="SSID">&quot;Corp_Secure&quot;</string>
        <string name="PreSharedKey">null</string>
        <string name="KeyMgmt">WPA_EAP IEEE8021X</string>
      </WifiConfiguration>
    </Network>
    <Network>
      <WifiConfiguration>
        <string name="ConfigKey">&quot;Home_Fiber&quot;WPA_PSK</string>
        <string name="SSID">&quot;Home_Fiber&quot;</string>
        <string name="PreSharedKey">&quot;SuperSecretWiFiPass&quot;</string>
        <string name="KeyMgmt">WPA_PSK</string>
      </WifiConfiguration>
    </Network>
    <Network>
      <!-- ConfigKey fallback when SSID tag is omitted -->
      <WifiConfiguration>
        <string name="ConfigKey">&quot;LegacyAP&quot;WPA_PSK</string>
        <string name="PreSharedKey">&quot;OldPass123&quot;</string>
        <string name="KeyMgmt">WPA_PSK</string>
      </WifiConfiguration>
    </Network>
  </NetworkList>
</WifiConfigStoreData>
"""
    xml_file = tmp_path / "WifiConfigStore.xml"
    xml_file.write_text(xml_content, encoding="utf-8")

    results = parse_wifi_config_store_xml(xml_file)
    assert len(results) == 3

    ssids = {r[0]: (r[1], r[2]) for r in results}
    assert ssids["Corp_Secure"] == (None, "WPA_EAP IEEE8021X")
    assert ssids["Home_Fiber"] == ("SuperSecretWiFiPass", "WPA_PSK")
    assert ssids["LegacyAP"] == ("OldPass123", "WPA_PSK")


def test_wifi_extraction_modern_apex_path_with_root_staging(tmp_path: pathlib.Path) -> None:
    apex_wifi_xml = b"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<WifiConfigStoreData>
  <NetworkList>
    <Network>
      <WifiConfiguration>
        <string name="SSID">&quot;Android14_ApexWiFi&quot;</string>
        <string name="PreSharedKey">&quot;ApexPass2026&quot;</string>
        <string name="KeyMgmt">WPA_PSK</string>
      </WifiConfiguration>
    </Network>
  </NetworkList>
</WifiConfigStoreData>
"""
    remote_path = "/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml"
    dev = _MockDevicesWithFallback(remote_files={remote_path: apex_wifi_xml})

    creds = extract_wifi_passwords(dev, "TEST_SERIAL_123")  # type: ignore[arg-type]
    assert len(creds) == 1
    assert creds[0].ssid == "Android14_ApexWiFi"
    assert creds[0].psk == "ApexPass2026"
    assert creds[0].security == "WPA_PSK"


def test_pin_pull_gatekeeper_multiuser_with_staging(tmp_path: pathlib.Path) -> None:
    db_bytes = b"SQLite format 3\x00dummy-locksettings-db"
    key_bytes = b"dummy-gatekeeper-password-key-bytes"

    remote_db = "/data/system/users/0/locksettings.db"
    remote_key = "/data/system/users/0/gatekeeper.password.key"

    dev = _MockDevicesWithFallback(remote_files={
        remote_db: db_bytes,
        remote_key: key_bytes,
    })

    out_db = pull_locksettings_db(dev, "TEST_SERIAL", tmp_path / "pin_db")  # type: ignore[arg-type]
    assert out_db.exists()
    assert out_db.read_bytes() == db_bytes

    out_key = pull_password_key(dev, "TEST_SERIAL", tmp_path / "pin_key")  # type: ignore[arg-type]
    assert out_key.exists()
    assert out_key.read_bytes() == key_bytes


def test_gesture_pull_gatekeeper_multiuser_with_staging(tmp_path: pathlib.Path) -> None:
    key_bytes = b"dummy-gatekeeper-pattern-key"
    remote_key = "/data/system/users/0/gatekeeper.pattern.key"

    dev = _MockDevicesWithFallback(remote_files={
        remote_key: key_bytes,
    })

    out_key = pull_gesture_key(dev, "TEST_SERIAL", tmp_path / "gesture_key")  # type: ignore[arg-type]
    assert out_key.exists()
    assert out_key.read_bytes() == key_bytes


def test_gesture_synthetic_password_diagnostic(tmp_path: pathlib.Path) -> None:
    dev = _MockDevicesWithFallback(remote_files={}, spblob_present=True)

    with pytest.raises(GestureKeyNotFound) as exc_info:
        pull_gesture_key(dev, "TEST_SERIAL", tmp_path)  # type: ignore[arg-type]

    assert "Synthetic Password (spblob)" in str(exc_info.value)
    assert "hardware TEE" in str(exc_info.value)


def test_detect_synthetic_password_detection() -> None:
    dev_with_spblob = _MockDevicesWithFallback(remote_files={}, spblob_present=True)
    assert _detect_synthetic_password(dev_with_spblob, "TEST_SERIAL") is True  # type: ignore[arg-type]

    dev_without_spblob = _MockDevicesWithFallback(remote_files={}, spblob_present=False)
    assert _detect_synthetic_password(dev_without_spblob, "TEST_SERIAL") is False  # type: ignore[arg-type]


def test_keystore_candidate_paths_coverage() -> None:
    assert "/data/misc/keystore" in KEYSTORE_CANDIDATE_PATHS
    assert "/data/misc_ce/0/keystore" in KEYSTORE_CANDIDATE_PATHS
    assert "/data/misc_de/0/apexdata/com.android.security.keystore2" in KEYSTORE_CANDIDATE_PATHS
