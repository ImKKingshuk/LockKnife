from __future__ import annotations

import dataclasses
import re

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.logging import get_logger

log = get_logger()


@dataclasses.dataclass(frozen=True)
class LocationSnapshot:
    provider: str | None
    latitude: float | None
    longitude: float | None
    raw: str


@dataclasses.dataclass(frozen=True)
class WifiAccessPoint:
    ssid: str | None
    bssid: str | None
    level: int | None
    frequency: int | None
    raw: str


@dataclasses.dataclass(frozen=True)
class CellTower:
    kind: str
    mcc: int | None
    mnc: int | None
    lac: int | None = None
    cid: int | None = None
    tac: int | None = None
    eci: int | None = None
    pci: int | None = None
    raw: str | None = None


@dataclasses.dataclass(frozen=True)
class LocationArtifacts:
    snapshot: LocationSnapshot
    wifi: list[WifiAccessPoint]
    cell: list[CellTower]
    location_raw: str
    wifi_raw: str
    telephony_raw: str


def extract_location_snapshot(devices: DeviceManager, serial: str) -> LocationSnapshot:
    if not devices.has_root(serial):
        raise DeviceError("Root required to query location services")
    raw = devices.shell(serial, 'su -c "dumpsys location 2>/dev/null | head -n 200"', timeout_s=20.0)
    lat = None
    lon = None
    provider = None
    for ln in raw.splitlines():
        s = ln.strip()
        if "provider=" in s and provider is None:
            idx = s.find("provider=")
            provider = s[idx + 9 :].split()[0]
        if "lat=" in s and "lon=" in s:
            try:
                parts = s.replace(",", " ").split()
                for p in parts:
                    if p.startswith("lat="):
                        lat = float(p.split("=", 1)[1])
                    if p.startswith("lon="):
                        lon = float(p.split("=", 1)[1])
            except Exception:
                log.warning("location_parse_failed", exc_info=True, serial=serial)
    return LocationSnapshot(provider=provider, latitude=lat, longitude=lon, raw=raw)


_RE_BSSID = re.compile(r"(?i)\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b")
_RE_SSID = re.compile(r"SSID:\s*(?P<ssid>.+?)(?:,|\s+BSSID:|\s*$)")
_RE_LEVEL = re.compile(r"level:\s*(?P<level>-?\d+)")
_RE_FREQ = re.compile(r"frequency:\s*(?P<freq>\d+)")


def _parse_wifi_scan(raw: str, limit: int = 50) -> list[WifiAccessPoint]:
    out: list[WifiAccessPoint] = []
    for ln in raw.splitlines():
        s = ln.strip()
        if not s:
            continue
        bssid_m = _RE_BSSID.search(s)
        if not bssid_m:
            continue
        ssid_m = _RE_SSID.search(s)
        level_m = _RE_LEVEL.search(s)
        freq_m = _RE_FREQ.search(s)
        out.append(
            WifiAccessPoint(
                ssid=(ssid_m.group("ssid").strip() if ssid_m else None),
                bssid=bssid_m.group(0),
                level=int(level_m.group("level")) if level_m else None,
                frequency=int(freq_m.group("freq")) if freq_m else None,
                raw=s,
            )
        )
        if len(out) >= limit:
            break
    return out


def _int_from_token(tok: str) -> int | None:
    try:
        if tok.lower().startswith("0x"):
            return int(tok, 16)
        return int(tok)
    except Exception:
        return None


def _parse_cell_towers(raw: str, limit: int = 20) -> list[CellTower]:
    out: list[CellTower] = []
    for ln in raw.splitlines():
        s = ln.strip()
        if "CellIdentity" not in s and "mCellInfo" not in s and "cellIdentity" not in s:
            continue
        mcc = None
        mnc = None
        lac = None
        cid = None
        tac = None
        eci = None
        pci = None
        kind = "unknown"

        for key in ["mMcc=", "mnc=", "mMnc=", "mLac=", "lac=", "mCid=", "cid=", "mTac=", "tac=", "mEci=", "eci=", "mPci=", "pci="]:
            if key not in s:
                continue
            val = s.split(key, 1)[1].split(",", 1)[0].split(" ", 1)[0].strip(")];")
            n = _int_from_token(val)
            if key in {"mMcc=", "mcc="}:
                mcc = n
            elif key in {"mMnc=", "mnc="}:
                mnc = n
            elif key in {"mLac=", "lac="}:
                lac = n
            elif key in {"mCid=", "cid="}:
                cid = n
            elif key in {"mTac=", "tac="}:
                tac = n
            elif key in {"mEci=", "eci="}:
                eci = n
            elif key in {"mPci=", "pci="}:
                pci = n

        if "CellIdentityLte" in s or "LTE" in s:
            kind = "lte"
        elif "CellIdentityNr" in s or "NR" in s or "5G" in s:
            kind = "nr"
        elif "CellIdentityGsm" in s or "GSM" in s:
            kind = "gsm"
        elif "CellIdentityWcdma" in s or "WCDMA" in s or "UMTS" in s:
            kind = "wcdma"

        out.append(CellTower(kind=kind, mcc=mcc, mnc=mnc, lac=lac, cid=cid, tac=tac, eci=eci, pci=pci, raw=s))
        if len(out) >= limit:
            break
    return out


def extract_location_artifacts(devices: DeviceManager, serial: str) -> LocationArtifacts:
    if not devices.has_root(serial):
        raise DeviceError("Root required to query location services")

    location_raw = devices.shell(serial, 'su -c "dumpsys location 2>/dev/null"', timeout_s=40.0)
    wifi_raw = devices.shell(serial, 'su -c "dumpsys wifi 2>/dev/null"', timeout_s=40.0)
    telephony_raw = devices.shell(serial, 'su -c "dumpsys telephony.registry 2>/dev/null"', timeout_s=40.0)

    snap = extract_location_snapshot(devices, serial)
    wifi = _parse_wifi_scan(wifi_raw)
    cell = _parse_cell_towers(telephony_raw)
    return LocationArtifacts(snapshot=snap, wifi=wifi, cell=cell, location_raw=location_raw, wifi_raw=wifi_raw, telephony_raw=telephony_raw)
