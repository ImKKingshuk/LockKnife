import pathlib
import sqlite3
import types

import pytest

from lockknife.modules.extraction.browser import (
    _parse_chrome_bookmarks,
    _parse_chrome_cookies,
    _parse_chrome_downloads,
    _parse_chrome_history,
    _parse_chrome_logins,
    _parse_firefox_logins,
    _parse_firefox_places_bookmarks,
    _parse_firefox_places_history,
    extract_chrome_bookmarks,
    extract_chrome_cookies,
    extract_chrome_downloads,
    extract_chrome_history,
    extract_chrome_saved_logins,
    extract_firefox_bookmarks,
    extract_firefox_history,
    extract_firefox_saved_logins,
)
from lockknife.core.exceptions import DeviceError


def test_parse_chrome_history(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "History"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE urls (url TEXT, title TEXT, last_visit_time INTEGER, visit_count INTEGER)")
        con.execute("INSERT INTO urls VALUES ('https://a', 'A', 2, 1)")
        con.execute("INSERT INTO urls VALUES ('https://b', 'B', 3, 2)")
        con.commit()
    finally:
        con.close()
    rows = _parse_chrome_history(db, 10)
    assert rows[0].url == "https://b"


def test_parse_chrome_bookmarks(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "Bookmarks"
    p.write_text(
        '{"roots":{"bookmark_bar":{"children":[{"type":"url","name":"A","url":"https://a","date_added":"1"}]}}}',
        encoding="utf-8",
    )
    rows = _parse_chrome_bookmarks(p, 10)
    assert rows[0].url == "https://a"
    assert rows[0].title == "A"


def test_parse_chrome_downloads(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "History"
    con = sqlite3.connect(str(db))
    try:
        con.execute(
            "CREATE TABLE downloads (tab_url TEXT, target_path TEXT, start_time INTEGER, end_time INTEGER, received_bytes INTEGER)"
        )
        con.execute("INSERT INTO downloads VALUES ('https://x', '/sdcard/x', 1, 2, 3)")
        con.commit()
    finally:
        con.close()
    rows = _parse_chrome_downloads(db, 10)
    assert rows[0].url == "https://x"


def test_parse_chrome_cookies_and_logins(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "Cookies"
    con = sqlite3.connect(str(db))
    try:
        con.execute(
            "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, expires_utc INTEGER, last_access_utc INTEGER)"
        )
        con.execute("INSERT INTO cookies VALUES ('example.com','sid','v',X'0102',1,2)")
        con.execute(
            "CREATE TABLE logins (origin_url TEXT, username_value TEXT, encrypted_password BLOB)"
        )
        con.execute("INSERT INTO logins VALUES ('https://example.com','u',X'0A0B')")
        con.commit()
    finally:
        con.close()
    cookies = _parse_chrome_cookies(db, 10)
    assert cookies[0].host == "example.com"
    logins = _parse_chrome_logins(db, 10)
    assert logins[0].origin_url == "https://example.com"
    assert logins[0].password_encrypted_b64 is not None


def test_parse_firefox_places(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "places.sqlite"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_date INTEGER, visit_count INTEGER)")
        con.execute("INSERT INTO moz_places(id,url,title,last_visit_date,visit_count) VALUES (1,'https://a','A',2,1)")
        con.execute("CREATE TABLE moz_bookmarks (fk INTEGER, title TEXT, dateAdded INTEGER)")
        con.execute("INSERT INTO moz_bookmarks VALUES (1,'B',3)")
        con.commit()
    finally:
        con.close()
    hist = _parse_firefox_places_history(db, 10)
    assert hist[0].url == "https://a"
    bms = _parse_firefox_places_bookmarks(db, 10)
    assert bms[0].url == "https://a"


def test_parse_firefox_logins(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "logins.json"
    p.write_text('{"logins":[{"hostname":"https://x","encryptedUsername":"EU","encryptedPassword":"EP"}]}', encoding="utf-8")
    rows = _parse_firefox_logins(p, 10)
    assert rows[0].origin_url == "https://x"


def test_extract_chromium_variant_uses_variant_paths(monkeypatch, tmp_path: pathlib.Path) -> None:
    import lockknife.modules.extraction._browser_extract_chrome as chrome_extract

    db = tmp_path / "History"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE urls (url TEXT, title TEXT, last_visit_time INTEGER, visit_count INTEGER)")
        con.execute("INSERT INTO urls VALUES ('https://edge.example', 'Edge', 3, 1)")
        con.commit()
    finally:
        con.close()

    seen: list[str] = []

    def _pull(_devices, _serial, remote, local, timeout_s=120.0):
        seen.append(remote)
        if "com.microsoft.emmx" in remote:
            local.write_bytes(db.read_bytes())
            return True
        return False

    monkeypatch.setattr(chrome_extract, "_try_root_pull_file", _pull)
    rows = extract_chrome_history(types.SimpleNamespace(has_root=lambda _serial: True), "SERIAL", browser="edge")
    assert rows[0].url == "https://edge.example"
    assert any("com.microsoft.emmx" in path for path in seen)


def test_extract_chrome_history_requires_root() -> None:
    with pytest.raises(DeviceError):
        extract_chrome_history(types.SimpleNamespace(has_root=lambda _serial: False), "SERIAL")


def test_extract_chrome_bookmarks_retries_parse_failures(monkeypatch, tmp_path: pathlib.Path) -> None:
    import lockknife.modules.extraction._browser_extract_chrome as chrome_extract

    local_copy = tmp_path / "Bookmarks"
    local_copy.write_text("{}", encoding="utf-8")
    attempts: list[str] = []

    def _pull(_devices, _serial, remote, local, timeout_s=120.0):
        attempts.append(remote)
        local.write_text(local_copy.read_text(encoding="utf-8"), encoding="utf-8")
        return True

    monkeypatch.setattr(chrome_extract, "_try_root_pull_file", _pull)
    monkeypatch.setattr(chrome_extract, "_parse_chrome_bookmarks", lambda *_a, **_k: (_ for _ in ()).throw(ValueError("bad json")))

    with pytest.raises(DeviceError):
        extract_chrome_bookmarks(types.SimpleNamespace(has_root=lambda _serial: True), "SERIAL", browser="opera")
    assert any("com.opera.browser" in path for path in attempts)


def test_extract_chrome_downloads_returns_empty_on_sqlite_errors(monkeypatch) -> None:
    import lockknife.modules.extraction._browser_extract_chrome as chrome_extract

    monkeypatch.setattr(chrome_extract, "_try_root_pull_file", lambda *_a, **_k: True)
    monkeypatch.setattr(chrome_extract, "_parse_chrome_downloads", lambda *_a, **_k: (_ for _ in ()).throw(sqlite3.Error("bad db")))
    rows = extract_chrome_downloads(types.SimpleNamespace(has_root=lambda _serial: True), "SERIAL", browser="brave")
    assert rows == []


def test_extract_chrome_cookies_returns_empty_when_no_items(monkeypatch) -> None:
    import lockknife.modules.extraction._browser_extract_chrome as chrome_extract

    monkeypatch.setattr(chrome_extract, "_try_root_pull_file", lambda *_a, **_k: True)
    monkeypatch.setattr(chrome_extract, "_parse_chrome_cookies", lambda *_a, **_k: [])
    rows = extract_chrome_cookies(types.SimpleNamespace(has_root=lambda _serial: True), "SERIAL")
    assert rows == []


def test_extract_chrome_saved_logins_uses_default_package_fallback(monkeypatch, tmp_path: pathlib.Path) -> None:
    import lockknife.modules.extraction._browser_extract_chrome as chrome_extract

    db = tmp_path / "Login Data"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE logins (origin_url TEXT, username_value TEXT, encrypted_password BLOB)")
        con.execute("INSERT INTO logins VALUES ('https://site.example','u',X'0A0B')")
        con.commit()
    finally:
        con.close()

    seen: list[str] = []

    def _pull(_devices, _serial, remote, local, timeout_s=120.0):
        seen.append(remote)
        local.write_bytes(db.read_bytes())
        return True

    monkeypatch.setattr(chrome_extract, "_try_root_pull_file", _pull)
    rows = extract_chrome_saved_logins(types.SimpleNamespace(has_root=lambda _serial: True), "SERIAL", browser="unknown")
    assert rows[0].origin_url == "https://site.example"
    assert any("com.android.chrome" in path for path in seen)


def test_extract_firefox_history_requires_root() -> None:
    with pytest.raises(DeviceError):
        extract_firefox_history(types.SimpleNamespace(has_root=lambda _serial: False), "SERIAL")


def test_extract_firefox_history_reads_profile_db(monkeypatch, tmp_path: pathlib.Path) -> None:
    import lockknife.modules.extraction._browser_extract_firefox as firefox_extract

    db = tmp_path / "places.sqlite"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_date INTEGER, visit_count INTEGER)")
        con.execute("INSERT INTO moz_places(id,url,title,last_visit_date,visit_count) VALUES (1,'https://firefox.example','F',2,1)")
        con.commit()
    finally:
        con.close()

    def _pull(_devices, _serial, _remote, local, timeout_s=180.0):
        local.write_bytes(db.read_bytes())
        return True

    monkeypatch.setattr(firefox_extract, "_try_root_pull_file", _pull)
    devices = types.SimpleNamespace(has_root=lambda _serial: True, shell=lambda *_a, **_k: "/data/data/org.mozilla.firefox/files/mozilla/abc.default\n")

    rows = extract_firefox_history(devices, "SERIAL")
    assert rows[0].url == "https://firefox.example"


def test_extract_firefox_bookmarks_ignores_shell_and_sqlite_errors(monkeypatch) -> None:
    import lockknife.modules.extraction._browser_extract_firefox as firefox_extract

    attempts = {"count": 0}

    def _shell(_serial, _command, timeout_s=20.0):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("ls failed")
        return "/data/data/org.mozilla.fenix/files/mozilla/abc.default\n"

    monkeypatch.setattr(firefox_extract, "_try_root_pull_file", lambda *_a, **_k: True)
    monkeypatch.setattr(firefox_extract, "_parse_firefox_places_bookmarks", lambda *_a, **_k: (_ for _ in ()).throw(sqlite3.Error("bad db")))
    devices = types.SimpleNamespace(has_root=lambda _serial: True, shell=_shell)

    rows = extract_firefox_bookmarks(devices, "SERIAL")
    assert rows == []
    assert attempts["count"] >= 2


def test_extract_firefox_saved_logins_retries_after_parse_failure(monkeypatch, tmp_path: pathlib.Path) -> None:
    import lockknife.modules.extraction._browser_extract_firefox as firefox_extract

    login_file = tmp_path / "logins.json"
    login_file.write_text('{"logins":[{"hostname":"https://retry.example","encryptedUsername":"U","encryptedPassword":"P"}]}', encoding="utf-8")
    original_parse = firefox_extract._parse_firefox_logins
    attempts = {"count": 0}

    def _pull(_devices, _serial, _remote, local, timeout_s=120.0):
        local.write_text(login_file.read_text(encoding="utf-8"), encoding="utf-8")
        return True

    def _parse(local, limit):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise ValueError("bad json")
        return original_parse(local, limit)

    monkeypatch.setattr(firefox_extract, "_try_root_pull_file", _pull)
    monkeypatch.setattr(firefox_extract, "_parse_firefox_logins", _parse)
    devices = types.SimpleNamespace(
        has_root=lambda _serial: True,
        shell=lambda *_a, **_k: "/data/data/org.mozilla.firefox/files/mozilla/a.default\n/data/data/org.mozilla.fenix/files/mozilla/b.default\n",
    )

    rows = extract_firefox_saved_logins(devices, "SERIAL")
    assert rows[0].origin_url == "https://retry.example"
    assert attempts["count"] == 2


@pytest.mark.parametrize(
    ("func", "message"),
    [
        (extract_firefox_history, "history"),
        (extract_firefox_bookmarks, "bookmarks"),
        (extract_firefox_saved_logins, "passwords"),
    ],
)
def test_extract_firefox_validates_limit_and_root(func, message: str) -> None:
    with pytest.raises(ValueError, match="limit must be > 0"):
        func(types.SimpleNamespace(has_root=lambda _serial: True), "SERIAL", limit=0)
    with pytest.raises(DeviceError, match=message):
        func(types.SimpleNamespace(has_root=lambda _serial: False), "SERIAL")


def test_extract_firefox_bookmarks_retries_after_empty_parse(monkeypatch, tmp_path: pathlib.Path) -> None:
    import lockknife.modules.extraction._browser_extract_firefox as firefox_extract

    db = tmp_path / "places.sqlite"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, fk INTEGER, title TEXT, type INTEGER)")
        con.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT)")
        con.execute("INSERT INTO moz_places(id,url) VALUES (1,'https://bookmark.example')")
        con.execute("INSERT INTO moz_bookmarks(id,fk,title,type) VALUES (1,1,'Bookmark',1)")
        con.commit()
    finally:
        con.close()

    original_parse = firefox_extract._parse_firefox_places_bookmarks
    calls = {"count": 0}

    def _pull(_devices, _serial, _remote, local, timeout_s=180.0):
        local.write_bytes(db.read_bytes())
        return True

    def _parse(local, limit):
        calls["count"] += 1
        if calls["count"] == 1:
            return []
        return original_parse(local, limit)

    monkeypatch.setattr(firefox_extract, "_try_root_pull_file", _pull)
    monkeypatch.setattr(firefox_extract, "_parse_firefox_places_bookmarks", _parse)
    devices = types.SimpleNamespace(
        has_root=lambda _serial: True,
        shell=lambda *_a, **_k: "/data/data/org.mozilla.firefox/files/mozilla/a.default\n/data/data/org.mozilla.fenix/files/mozilla/b.default\n",
    )

    rows = extract_firefox_bookmarks(devices, "SERIAL")
    assert rows[0].url == "https://bookmark.example"
    assert calls["count"] == 2


def test_extract_firefox_saved_logins_retries_after_pull_failure(monkeypatch, tmp_path: pathlib.Path) -> None:
    import lockknife.modules.extraction._browser_extract_firefox as firefox_extract

    login_file = tmp_path / "logins.json"
    login_file.write_text('{"logins":[{"hostname":"https://fallback.example","encryptedUsername":"U","encryptedPassword":"P"}]}', encoding="utf-8")
    attempts = {"count": 0}

    def _pull(_devices, _serial, _remote, local, timeout_s=120.0):
        attempts["count"] += 1
        if attempts["count"] == 1:
            return False
        local.write_text(login_file.read_text(encoding="utf-8"), encoding="utf-8")
        return True

    monkeypatch.setattr(firefox_extract, "_try_root_pull_file", _pull)
    devices = types.SimpleNamespace(
        has_root=lambda _serial: True,
        shell=lambda *_a, **_k: "/data/data/org.mozilla.firefox/files/mozilla/a.default\n/data/data/org.mozilla.fenix/files/mozilla/b.default\n",
    )

    rows = extract_firefox_saved_logins(devices, "SERIAL")
    assert rows[0].origin_url == "https://fallback.example"
    assert attempts["count"] == 2
