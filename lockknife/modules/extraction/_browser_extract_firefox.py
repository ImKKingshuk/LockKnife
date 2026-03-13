from __future__ import annotations



import sqlite3



from lockknife.core.device import DeviceManager

from lockknife.core.exceptions import DeviceError

from lockknife.core.security import secure_temp_dir

from lockknife.modules.extraction._browser_common import _try_root_pull_file, log
from lockknife.modules.extraction._browser_models import BrowserBookmarkEntry, BrowserHistoryEntry, BrowserLoginEntry

from lockknife.modules.extraction._browser_parse_firefox import _parse_firefox_logins, _parse_firefox_places_bookmarks, _parse_firefox_places_history



def extract_firefox_history(devices: DeviceManager, serial: str, limit: int = 500) -> list[BrowserHistoryEntry]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access Firefox history")

    profile_globs = [
        "/data/data/org.mozilla.firefox/files/mozilla/*.default*",
        "/data/data/org.mozilla.fenix/files/mozilla/*.default*",
    ]
    with secure_temp_dir(prefix="lockknife-browser-") as d:
        for g in profile_globs:
            try:
                raw = devices.shell(serial, f'su -c "ls -1d {g} 2>/dev/null"', timeout_s=20.0)
            except Exception:
                log.debug("firefox_profile_glob_failed", exc_info=True, serial=serial, glob=g)
                continue
            for prof in [ln.strip() for ln in raw.splitlines() if ln.strip()]:
                remote = f"{prof}/places.sqlite"
                local = d / "places.sqlite"
                if not _try_root_pull_file(devices, serial, remote, local, timeout_s=180.0):
                    continue
                try:
                    items = _parse_firefox_places_history(local, limit)
                    if items:
                        return items
                except sqlite3.Error:
                    continue
    return []

def extract_firefox_bookmarks(devices: DeviceManager, serial: str, limit: int = 2000) -> list[BrowserBookmarkEntry]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access Firefox bookmarks")

    profile_globs = [
        "/data/data/org.mozilla.firefox/files/mozilla/*.default*",
        "/data/data/org.mozilla.fenix/files/mozilla/*.default*",
    ]
    with secure_temp_dir(prefix="lockknife-browser-") as d:
        for g in profile_globs:
            try:
                raw = devices.shell(serial, f'su -c "ls -1d {g} 2>/dev/null"', timeout_s=20.0)
            except Exception:
                log.debug("firefox_profile_glob_failed", exc_info=True, serial=serial, glob=g)
                continue
            for prof in [ln.strip() for ln in raw.splitlines() if ln.strip()]:
                remote = f"{prof}/places.sqlite"
                local = d / "places.sqlite"
                if not _try_root_pull_file(devices, serial, remote, local, timeout_s=180.0):
                    continue
                try:
                    items = _parse_firefox_places_bookmarks(local, limit)
                    if items:
                        return items
                except sqlite3.Error:
                    continue
    return []

def extract_firefox_saved_logins(devices: DeviceManager, serial: str, limit: int = 500) -> list[BrowserLoginEntry]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError("Root required to access Firefox saved passwords")

    profile_globs = [
        "/data/data/org.mozilla.firefox/files/mozilla/*.default*",
        "/data/data/org.mozilla.fenix/files/mozilla/*.default*",
    ]
    with secure_temp_dir(prefix="lockknife-browser-") as d:
        for g in profile_globs:
            try:
                raw = devices.shell(serial, f'su -c "ls -1d {g} 2>/dev/null"', timeout_s=20.0)
            except Exception:
                log.debug("firefox_profile_glob_failed", exc_info=True, serial=serial, glob=g)
                continue
            for prof in [ln.strip() for ln in raw.splitlines() if ln.strip()]:
                remote = f"{prof}/logins.json"
                local = d / "logins.json"
                if not _try_root_pull_file(devices, serial, remote, local, timeout_s=120.0):
                    continue
                try:
                    items = _parse_firefox_logins(local, limit)
                    if items:
                        return items
                except Exception:
                    log.debug("firefox_logins_parse_failed", exc_info=True, serial=serial, local_path=str(local))
                    continue
    return []
