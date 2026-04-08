import json
import pathlib
import sqlite3


class _Adb:
    def __init__(
        self, fixtures: dict[str, pathlib.Path], *, firefox_profile: str | None = None
    ) -> None:
        self._fixtures = fixtures
        self._firefox_profile = firefox_profile

    def pull(
        self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0
    ) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        name = pathlib.PurePosixPath(remote_path).name
        src = self._fixtures.get(name)
        if src is None:
            raise FileNotFoundError(remote_path)
        local_path.write_bytes(src.read_bytes())

    def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
        if (
            "ls -1d /data/data/org.mozilla.firefox/files/mozilla/" in command
            and self._firefox_profile
        ):
            return self._firefox_profile + "\n"
        if command.startswith('su -c "ls -1t'):
            return "a.jpg\n"
        return ""

    def has_su(self, serial: str) -> bool:
        return True

    def getprop(self, serial: str) -> dict[str, str]:
        return {}


class _Devices:
    def __init__(self, adb: _Adb) -> None:
        self._adb = adb

    def pull(
        self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0
    ) -> None:
        return self._adb.pull(serial, remote_path, local_path, timeout_s=timeout_s)

    def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
        return self._adb.shell(serial, command, timeout_s=timeout_s)

    def has_root(self, serial: str) -> bool:
        return True


def _mk_chrome_history(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "History"
    con = sqlite3.connect(str(p))
    try:
        con.execute(
            "CREATE TABLE urls (url TEXT, title TEXT, last_visit_time INTEGER, visit_count INTEGER)"
        )
        con.execute("INSERT INTO urls VALUES ('https://example.com', 't', 1, 2)")
        con.execute(
            "CREATE TABLE downloads (tab_url TEXT, target_path TEXT, start_time INTEGER, end_time INTEGER, received_bytes INTEGER)"
        )
        con.execute("INSERT INTO downloads VALUES ('https://d', '/tmp/x', 1, 2, 3)")
        con.commit()
    finally:
        con.close()
    return p


def _mk_chrome_login(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "chrome.sqlite"
    con = sqlite3.connect(str(p))
    try:
        con.execute(
            "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value TEXT, encrypted_password BLOB)"
        )
        con.execute("INSERT INTO logins VALUES ('https://x', 'u', 'p', X'0102')")
        con.commit()
    finally:
        con.close()
    return p


def _mk_chrome_cookies(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "Cookies"
    con = sqlite3.connect(str(p))
    try:
        con.execute(
            "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, expires_utc INTEGER, last_access_utc INTEGER)"
        )
        con.execute("INSERT INTO cookies VALUES ('h', 'n', 'v', X'AA', 1, 2)")
        con.commit()
    finally:
        con.close()
    return p


def _mk_firefox_places(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "places.sqlite"
    con = sqlite3.connect(str(p))
    try:
        con.execute(
            "CREATE TABLE moz_places (id INTEGER, url TEXT, title TEXT, last_visit_date INTEGER, visit_count INTEGER)"
        )
        con.execute("INSERT INTO moz_places VALUES (1, 'https://f', 'ft', 1, 2)")
        con.execute("CREATE TABLE moz_bookmarks (fk INTEGER, title TEXT, dateAdded INTEGER)")
        con.execute("INSERT INTO moz_bookmarks VALUES (1, 'bt', 10)")
        con.commit()
    finally:
        con.close()
    return p


def _mk_firefox_logins(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "logins.json"
    p.write_text(
        json.dumps(
            {"logins": [{"hostname": "https://f", "username": "u", "encryptedPassword": "x"}]}
        ),
        encoding="utf-8",
    )
    return p


def _mk_bookmarks_json(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "Bookmarks"
    p.write_text(
        json.dumps(
            {
                "roots": {
                    "bookmark_bar": {
                        "children": [
                            {"type": "url", "url": "https://b", "name": "B", "date_added": "1"}
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return p


def _mk_jpeg(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "a.jpg"
    p.write_bytes(b"\xff\xd8\xff\xd9")
    return p


def test_extract_browser_chrome_and_firefox(tmp_path) -> None:
    from lockknife.modules.extraction.browser import (
        extract_chrome_bookmarks,
        extract_chrome_cookies,
        extract_chrome_downloads,
        extract_chrome_history,
        extract_chrome_saved_logins,
        extract_firefox_bookmarks,
        extract_firefox_history,
        extract_firefox_saved_logins,
    )

    chrome_history = _mk_chrome_history(tmp_path)
    chrome_login = _mk_chrome_login(tmp_path)
    chrome_cookies = _mk_chrome_cookies(tmp_path)
    chrome_bookmarks = _mk_bookmarks_json(tmp_path)
    ff_places = _mk_firefox_places(tmp_path)
    ff_logins = _mk_firefox_logins(tmp_path)

    adb = _Adb(
        {
            "History": chrome_history,
            "chrome.sqlite": chrome_login,
            "Login Data": chrome_login,
            "Web Data": chrome_login,
            "lockknife-tmp-chrome.sqlite": chrome_login,
            "Cookies": chrome_cookies,
            "Bookmarks": chrome_bookmarks,
            "places.sqlite": ff_places,
            "logins.json": ff_logins,
        },
        firefox_profile="/data/data/org.mozilla.firefox/files/mozilla/abcd.default",
    )
    dev = _Devices(adb)

    h = extract_chrome_history(dev, "SER", limit=10)  # type: ignore[arg-type]
    assert h[0].url == "https://example.com"

    b = extract_chrome_bookmarks(dev, "SER", limit=10)  # type: ignore[arg-type]
    assert b[0].url == "https://b"

    c = extract_chrome_cookies(dev, "SER", limit=10)  # type: ignore[arg-type]
    assert c[0].host == "h"

    dls = extract_chrome_downloads(dev, "SER", limit=10)  # type: ignore[arg-type]
    assert dls[0].target_path == "/tmp/x"

    logins = extract_chrome_saved_logins(dev, "SER", limit=10)  # type: ignore[arg-type]
    assert logins[0].origin_url == "https://x"

    fh = extract_firefox_history(dev, "SER", limit=10)  # type: ignore[arg-type]
    assert fh[0].url == "https://f"

    fb = extract_firefox_bookmarks(dev, "SER", limit=10)  # type: ignore[arg-type]
    assert fb[0].url == "https://f"

    fl = extract_firefox_saved_logins(dev, "SER", limit=10)  # type: ignore[arg-type]
    assert fl[0].origin_url == "https://f"


def test_extract_media_with_exif(tmp_path) -> None:
    from lockknife.modules.extraction.media import extract_media_with_exif

    jpg = _mk_jpeg(tmp_path)
    adb = _Adb({"a.jpg": jpg})
    dev = _Devices(adb)
    rows = extract_media_with_exif(dev, "SER", limit=1)  # type: ignore[arg-type]
    assert rows[0].kind == "jpg"
    assert rows[0].gps_lat is None
    assert rows[0].gps_lon is None
