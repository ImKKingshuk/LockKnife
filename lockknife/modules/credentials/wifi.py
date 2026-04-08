from __future__ import annotations

import dataclasses
import pathlib

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger
from lockknife.core.security import secure_temp_dir
from lockknife.modules.credentials._wifi_parse import (
    parse_wifi_config_store_xml,
    parse_wpa_supplicant,
)

log = get_logger()


@dataclasses.dataclass(frozen=True)
class WifiCredential:
    """Saved WiFi network credential extracted from the device."""

    ssid: str
    psk: str | None
    security: str | None = None


@dataclasses.dataclass(frozen=True)
class WifiExtraction:
    serial: str
    source_remote_path: str
    source_local_path: pathlib.Path
    credentials: list[WifiCredential]
    candidate_paths: list[str]


def _parse_wpa_supplicant(text: str) -> list[WifiCredential]:
    return [
        WifiCredential(ssid=ssid, psk=psk, security=security)
        for ssid, psk, security in parse_wpa_supplicant(text)
    ]


def _parse_wifi_config_store_xml(path: pathlib.Path) -> list[WifiCredential]:
    return [
        WifiCredential(ssid=ssid, psk=psk, security=security)
        for ssid, psk, security in parse_wifi_config_store_xml(path)
    ]


def export_wifi_credentials(
    devices: DeviceManager, serial: str, output_dir: pathlib.Path
) -> WifiExtraction:
    if not devices.has_root(serial):
        raise DeviceError("Root required to access WiFi configs")
    output_dir.mkdir(parents=True, exist_ok=True)
    candidates = [
        "/data/misc/wifi/WifiConfigStore.xml",
        "/data/misc/wifi/wpa_supplicant.conf",
        "/data/wifi/bcm_supp.conf",
    ]
    for remote in candidates:
        local = output_dir / pathlib.Path(remote).name
        try:
            devices.pull(serial, remote, local, timeout_s=60.0)
        except Exception:
            log.debug("wifi_pull_failed", exc_info=True, serial=serial, remote_path=remote)
            continue
        if not local.exists() or local.stat().st_size == 0:
            continue
        try:
            rows = (
                _parse_wifi_config_store_xml(local)
                if local.suffix.lower() == ".xml"
                else _parse_wpa_supplicant(local.read_text(encoding="utf-8", errors="ignore"))
            )
        except Exception:
            log.debug("wifi_parse_failed", exc_info=True, serial=serial, local_path=str(local))
            continue
        return WifiExtraction(
            serial=serial,
            source_remote_path=remote,
            source_local_path=local,
            credentials=rows,
            candidate_paths=candidates,
        )
    raise DeviceError("No supported WiFi config file found")


def extract_wifi_passwords(devices: DeviceManager, serial: str) -> list[WifiCredential]:
    """Extract saved WiFi SSIDs and PSKs from a rooted Android device."""
    with secure_temp_dir(prefix="lockknife-wifi-") as d:
        return export_wifi_credentials(devices, serial, d).credentials
