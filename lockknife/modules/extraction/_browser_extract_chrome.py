from __future__ import annotations

import sqlite3

from lockknife.core.device import DeviceManager
from lockknife.core.exceptions import DeviceError
from lockknife.core.security import secure_temp_dir
from lockknife.modules.extraction._browser_common import _try_root_pull_file, log
from lockknife.modules.extraction._browser_models import (
    BrowserBookmarkEntry,
    BrowserCookieEntry,
    BrowserDownloadEntry,
    BrowserHistoryEntry,
    BrowserLoginEntry,
)
from lockknife.modules.extraction._browser_parse_chrome import (
    _parse_chrome_bookmarks,
    _parse_chrome_cookies,
    _parse_chrome_downloads,
    _parse_chrome_history,
    _parse_chrome_logins,
)

_CHROMIUM_BROWSER_PACKAGES = {
    "chrome": ["com.android.chrome", "com.chrome.beta"],
    "edge": ["com.microsoft.emmx"],
    "brave": ["com.brave.browser"],
    "opera": ["com.opera.browser", "com.opera.mini.native"],
}


def _candidate_paths(browser: str, relative_path: str) -> list[str]:
    package_names = _CHROMIUM_BROWSER_PACKAGES.get(browser, _CHROMIUM_BROWSER_PACKAGES["chrome"])
    out: list[str] = []
    for package_name in package_names:
        out.append(f"/data/data/{package_name}/app_chromium/Default/{relative_path}")
        out.append(f"/data/data/{package_name}/app_chrome/Default/{relative_path}")
        out.append(f"/data/user_de/0/{package_name}/app_chromium/Default/{relative_path}")
        out.append(f"/data/user_de/0/{package_name}/app_chrome/Default/{relative_path}")
    return out


def extract_chrome_history(
    devices: DeviceManager, serial: str, limit: int = 500, *, browser: str = "chrome"
) -> list[BrowserHistoryEntry]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError(f"Root required to access {browser.title()} history")

    candidates = _candidate_paths(browser, "History")
    with secure_temp_dir(prefix="lockknife-browser-") as d:
        for remote in candidates:
            local = d / "History"
            if not _try_root_pull_file(devices, serial, remote, local, timeout_s=120.0):
                continue
            try:
                return _parse_chrome_history(local, limit)
            except sqlite3.Error:
                continue

    raise DeviceError(f"Unable to extract {browser.title()} history")


def extract_chrome_bookmarks(
    devices: DeviceManager, serial: str, limit: int = 2000, *, browser: str = "chrome"
) -> list[BrowserBookmarkEntry]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError(f"Root required to access {browser.title()} bookmarks")

    candidates = _candidate_paths(browser, "Bookmarks")
    with secure_temp_dir(prefix="lockknife-browser-") as d:
        for remote in candidates:
            local = d / "Bookmarks"
            if not _try_root_pull_file(devices, serial, remote, local, timeout_s=120.0):
                continue
            try:
                return _parse_chrome_bookmarks(local, limit)
            except Exception:
                log.debug(
                    "chrome_bookmarks_parse_failed",
                    exc_info=True,
                    serial=serial,
                    local_path=str(local),
                )
                continue
    raise DeviceError(f"Unable to extract {browser.title()} bookmarks")


def extract_chrome_downloads(
    devices: DeviceManager, serial: str, limit: int = 500, *, browser: str = "chrome"
) -> list[BrowserDownloadEntry]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError(f"Root required to access {browser.title()} downloads")

    candidates = _candidate_paths(browser, "History")
    with secure_temp_dir(prefix="lockknife-browser-") as d:
        for remote in candidates:
            local = d / "History"
            if not _try_root_pull_file(devices, serial, remote, local, timeout_s=120.0):
                continue
            try:
                items = _parse_chrome_downloads(local, limit)
                if items:
                    return items
            except sqlite3.Error:
                continue
    return []


def extract_chrome_cookies(
    devices: DeviceManager, serial: str, limit: int = 1000, *, browser: str = "chrome"
) -> list[BrowserCookieEntry]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError(f"Root required to access {browser.title()} cookies")

    candidates = _candidate_paths(browser, "Cookies")
    with secure_temp_dir(prefix="lockknife-browser-") as d:
        for remote in candidates:
            local = d / "Cookies"
            if not _try_root_pull_file(devices, serial, remote, local, timeout_s=120.0):
                continue
            try:
                items = _parse_chrome_cookies(local, limit)
                if items:
                    return items
            except sqlite3.Error:
                continue
    return []


def extract_chrome_saved_logins(
    devices: DeviceManager, serial: str, limit: int = 500, *, browser: str = "chrome"
) -> list[BrowserLoginEntry]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if not devices.has_root(serial):
        raise DeviceError(f"Root required to access {browser.title()} saved passwords")

    candidates = _candidate_paths(browser, "Login Data") + _candidate_paths(browser, "Web Data")
    with secure_temp_dir(prefix="lockknife-browser-") as d:
        for remote in candidates:
            local = d / "chrome.sqlite"
            if not _try_root_pull_file(devices, serial, remote, local, timeout_s=120.0):
                continue
            try:
                items = _parse_chrome_logins(local, limit)
                if items:
                    return items
            except sqlite3.Error:
                continue
    return []
