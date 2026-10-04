from __future__ import annotations

import dataclasses
import re
from typing import Any

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
class LocationSettings:
    """Device-level location configuration from settings_secure."""
    location_mode: str | None = None
    location_providers_allowed: str | None = None
    high_accuracy: bool = False
    gps_enabled: bool = False
    network_enabled: bool = False
    mock_location: str | None = None


@dataclasses.dataclass(frozen=True)
class GnssStatus:
    """GNSS satellite and raw measurement metadata."""
    satellite_count: int = 0
    fix_type: str | None = None
    constellations: list[str] = dataclasses.field(default_factory=list)
    raw: str | None = None


@dataclasses.dataclass(frozen=True)
class LocationHistoryEntry:
    """A parsed Google Location History / timeline record."""
    timestamp: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    accuracy: int | None = None
    source: str | None = None


@dataclasses.dataclass(frozen=True)
class LocationArtifacts:
    snapshot: LocationSnapshot
    wifi: list[WifiAccessPoint]
    cell: list[CellTower]
    location_raw: str
    wifi_raw: str
    telephony_raw: str
    # --- Batch 7: Enhanced location data ---
    settings: LocationSettings = dataclasses.field(default_factory=LocationSettings)
    gnss: GnssStatus = dataclasses.field(default_factory=GnssStatus)
    location_history: list[LocationHistoryEntry] = dataclasses.field(default_factory=list)
    provider_summary: dict[str, Any] = dataclasses.field(default_factory=dict)
    posture: dict[str, Any] = dataclasses.field(default_factory=dict)


def extract_location_snapshot(devices: DeviceManager, serial: str) -> LocationSnapshot:
    has_root = devices.has_root(serial)
    cmd = (
        'su -c "dumpsys location 2>/dev/null | head -n 200"'
        if has_root
        else "dumpsys location 2>/dev/null | head -n 200"
    )
    raw = ""
    try:
        raw = devices.shell(serial, cmd, timeout_s=20.0)
    except DeviceError:
        if not has_root:
            raise DeviceError("Root required to query location services") from None
        raise

    if not raw.strip() and not has_root:
        raise DeviceError("Root required to query location services")

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

        for key in [
            "mMcc=",
            "mnc=",
            "mMnc=",
            "mLac=",
            "lac=",
            "mCid=",
            "cid=",
            "mTac=",
            "tac=",
            "mEci=",
            "eci=",
            "mPci=",
            "pci=",
        ]:
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

        out.append(
            CellTower(
                kind=kind, mcc=mcc, mnc=mnc, lac=lac, cid=cid, tac=tac, eci=eci, pci=pci, raw=s
            )
        )
        if len(out) >= limit:
            break
    return out


# --- Batch 7: New extraction capabilities ---


def _extract_location_settings(devices: DeviceManager, serial: str) -> LocationSettings:
    """Extract location configuration from Android settings."""
    has_root = devices.has_root(serial)

    def _setting(namespace: str, key: str) -> str | None:
        cmd = f'settings get {namespace} {key}'
        if has_root:
            cmd = f'su -c "{cmd}"'
        try:
            val = devices.shell(serial, cmd, timeout_s=10.0).strip()
            return val if val and val != "null" else None
        except Exception:
            return None

    location_mode = _setting("secure", "location_mode")
    providers_allowed = _setting("secure", "location_providers_allowed")
    mock_location = _setting("secure", "mock_location")

    # Parse mode
    mode_map = {"0": "off", "1": "sensors_only", "2": "battery_saving", "3": "high_accuracy"}
    mode_label = mode_map.get(location_mode or "", location_mode)

    # Parse providers
    providers = (providers_allowed or "").lower()
    gps_enabled = "gps" in providers
    network_enabled = "network" in providers
    high_accuracy = location_mode == "3" or (gps_enabled and network_enabled)

    return LocationSettings(
        location_mode=mode_label,
        location_providers_allowed=providers_allowed,
        high_accuracy=high_accuracy,
        gps_enabled=gps_enabled,
        network_enabled=network_enabled,
        mock_location=mock_location,
    )


def _extract_gnss_status(devices: DeviceManager, serial: str) -> GnssStatus:
    """Extract GNSS satellite and measurement metadata."""
    has_root = devices.has_root(serial)
    cmd = (
        'su -c "dumpsys location | grep -A 50 gnss 2>/dev/null | head -n 60"'
        if has_root
        else 'dumpsys location 2>/dev/null | grep -A 50 gnss | head -n 60'
    )
    try:
        raw = devices.shell(serial, cmd, timeout_s=20.0)
    except Exception:
        log.debug("gnss_probe_failed", exc_info=True, serial=serial)
        return GnssStatus()

    if not raw.strip():
        return GnssStatus()

    # Extract satellite count
    sat_count = 0
    sat_m = re.search(r"(?:num_svs|satellite_count|svCount)[=:]\s*(\d+)", raw, re.IGNORECASE)
    if sat_m:
        sat_count = int(sat_m.group(1))

    # Extract fix type
    fix_type = None
    fix_m = re.search(r"(?:fix_type|fixType)[=:]\s*(\d+)", raw, re.IGNORECASE)
    if fix_m:
        fix_map = {"0": "no_fix", "1": "gps", "2": "dgps", "3": "pps", "4": "rtk", "5": "float_rtk"}
        fix_type = fix_map.get(fix_m.group(1), f"type_{fix_m.group(1)}")

    # Extract constellations
    constellations: list[str] = []
    constellation_names = {"GPS", "GLONASS", "GALILEO", "BEIDOU", "QZSS", "SBAS", "IRNSS", "NAVIC"}
    raw_upper = raw.upper()
    for name in constellation_names:
        if name in raw_upper:
            constellations.append(name)

    return GnssStatus(
        satellite_count=sat_count,
        fix_type=fix_type,
        constellations=sorted(constellations),
        raw=raw,
    )


def _extract_location_history(
    devices: DeviceManager, serial: str, limit: int = 50
) -> list[LocationHistoryEntry]:
    """Attempt to extract Google Location History entries from known database paths."""
    has_root = devices.has_root(serial)
    if not has_root:
        return []

    history: list[LocationHistoryEntry] = []
    db_paths = [
        "/data/data/com.google.android.gms/databases/history_db",
        "/data/user/0/com.google.android.gms/databases/history_db",
        "/data/data/com.google.android.gms/databases/gms_location.db",
    ]

    for db_path in db_paths:
        cmd = (
            f'su -c "sqlite3 {db_path} '
            f"\\\"SELECT timestamp, latitude, longitude, accuracy, source "
            f"FROM location_history ORDER BY timestamp DESC LIMIT {limit}\\\" 2>/dev/null\""
        )
        try:
            raw = devices.shell(serial, cmd, timeout_s=20.0)
        except Exception:
            continue

        if not raw.strip():
            continue

        for ln in raw.strip().splitlines():
            parts = ln.split("|")
            if len(parts) < 3:
                continue
            try:
                ts = parts[0].strip() if parts[0].strip() else None
                lat_val = float(parts[1]) if parts[1].strip() else None
                lon_val = float(parts[2]) if parts[2].strip() else None
                acc = int(parts[3]) if len(parts) > 3 and parts[3].strip() else None
                src = parts[4].strip() if len(parts) > 4 and parts[4].strip() else None
            except (ValueError, IndexError):
                continue

            # Google stores lat/lon as E7 integers in some schemas
            if lat_val and abs(lat_val) > 1_000_000:
                lat_val = lat_val / 1e7
            if lon_val and abs(lon_val) > 1_000_000:
                lon_val = lon_val / 1e7

            history.append(
                LocationHistoryEntry(
                    timestamp=ts, latitude=lat_val, longitude=lon_val, accuracy=acc, source=src
                )
            )

        if history:
            break

    return history[:limit]


def _build_provider_summary(
    location_raw: str, settings: LocationSettings, gnss: GnssStatus
) -> dict[str, Any]:
    """Build a summary of location provider capabilities and status."""
    providers: list[dict[str, Any]] = []

    if settings.gps_enabled:
        providers.append({
            "name": "gps",
            "enabled": True,
            "satellites": gnss.satellite_count,
            "constellations": gnss.constellations,
        })
    else:
        providers.append({"name": "gps", "enabled": False})

    if settings.network_enabled:
        providers.append({"name": "network", "enabled": True})
    else:
        providers.append({"name": "network", "enabled": False})

    # Check for fused provider
    if "fused" in location_raw.lower():
        providers.append({"name": "fused", "enabled": True})

    return {
        "mode": settings.location_mode,
        "high_accuracy": settings.high_accuracy,
        "mock_location_enabled": settings.mock_location not in {None, "0", "false"},
        "providers": providers,
        "provider_count": len(providers),
    }


def _assess_location_posture(
    settings: LocationSettings,
    gnss: GnssStatus,
    history_count: int,
    wifi_count: int,
    cell_count: int,
) -> dict[str, Any]:
    """Derive a location data richness and privacy posture."""
    findings: list[dict[str, str]] = []

    # --- Location mode ---
    if settings.location_mode == "off":
        findings.append({
            "signal": "location_mode", "value": "off", "severity": "info",
            "detail": "Location services are disabled; no fresh location data will be available.",
        })
    elif settings.high_accuracy:
        findings.append({
            "signal": "location_mode", "value": "high_accuracy", "severity": "ok",
            "detail": "High-accuracy mode combines GPS, network, and sensors for precise positioning.",
        })

    # --- Mock location ---
    if settings.mock_location and settings.mock_location not in {"0", "false"}:
        findings.append({
            "signal": "mock_location", "value": settings.mock_location, "severity": "warning",
            "detail": "Mock location provider is enabled; location data may be spoofed.",
        })

    # --- GNSS ---
    if gnss.satellite_count > 0:
        findings.append({
            "signal": "gnss_satellites", "value": str(gnss.satellite_count), "severity": "ok",
            "detail": f"{gnss.satellite_count} GNSS satellites visible across {len(gnss.constellations)} constellations.",
        })
    if gnss.constellations:
        findings.append({
            "signal": "gnss_constellations", "value": ", ".join(gnss.constellations), "severity": "info",
            "detail": f"Active constellations: {', '.join(gnss.constellations)}.",
        })

    # --- Data richness ---
    data_sources = 0
    if history_count > 0:
        data_sources += 1
        findings.append({
            "signal": "location_history", "value": str(history_count), "severity": "info",
            "detail": f"{history_count} Google Location History entries recovered.",
        })
    if wifi_count > 0:
        data_sources += 1
        findings.append({
            "signal": "wifi_aps", "value": str(wifi_count), "severity": "info",
            "detail": f"{wifi_count} nearby WiFi access points captured for positioning correlation.",
        })
    if cell_count > 0:
        data_sources += 1
        findings.append({
            "signal": "cell_towers", "value": str(cell_count), "severity": "info",
            "detail": f"{cell_count} cell tower identifiers captured for network-based positioning.",
        })

    richness = "rich" if data_sources >= 2 else ("moderate" if data_sources == 1 else "limited")

    return {
        "data_richness": richness,
        "data_source_count": data_sources,
        "findings": findings,
        "finding_count": len(findings),
    }


def extract_location_artifacts(devices: DeviceManager, serial: str) -> LocationArtifacts:
    has_root = devices.has_root(serial)
    loc_cmd = 'su -c "dumpsys location 2>/dev/null"' if has_root else "dumpsys location 2>/dev/null"
    wifi_cmd = 'su -c "dumpsys wifi 2>/dev/null"' if has_root else "dumpsys wifi 2>/dev/null"
    tel_cmd = (
        'su -c "dumpsys telephony.registry 2>/dev/null"'
        if has_root
        else "dumpsys telephony.registry 2>/dev/null"
    )

    try:
        location_raw = devices.shell(serial, loc_cmd, timeout_s=40.0)
        wifi_raw = devices.shell(serial, wifi_cmd, timeout_s=40.0)
        telephony_raw = devices.shell(serial, tel_cmd, timeout_s=40.0)
    except DeviceError:
        if not has_root:
            raise DeviceError("Root required to query location services") from None
        raise

    if (
        not location_raw.strip()
        and not wifi_raw.strip()
        and not telephony_raw.strip()
        and not has_root
    ):
        raise DeviceError("Root required to query location services")

    snap = extract_location_snapshot(devices, serial)
    wifi = _parse_wifi_scan(wifi_raw)
    cell = _parse_cell_towers(telephony_raw)

    # --- Batch 7: Enhanced extraction ---
    settings = _extract_location_settings(devices, serial)
    gnss = _extract_gnss_status(devices, serial)
    location_history = _extract_location_history(devices, serial)

    provider_summary = _build_provider_summary(location_raw, settings, gnss)
    posture = _assess_location_posture(
        settings=settings,
        gnss=gnss,
        history_count=len(location_history),
        wifi_count=len(wifi),
        cell_count=len(cell),
    )

    return LocationArtifacts(
        snapshot=snap,
        wifi=wifi,
        cell=cell,
        location_raw=location_raw,
        wifi_raw=wifi_raw,
        telephony_raw=telephony_raw,
        settings=settings,
        gnss=gnss,
        location_history=location_history,
        provider_summary=provider_summary,
        posture=posture,
    )
