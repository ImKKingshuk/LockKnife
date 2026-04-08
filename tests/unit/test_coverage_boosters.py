import struct
import zipfile

import pytest


def test_media_parse_exif_minimal(tmp_path) -> None:
    from lockknife.modules.extraction.media import _parse_exif_gps

    assert _parse_exif_gps(b"not-jpeg") == (None, None)

    exif = bytearray()
    exif.extend(b"II*\x00")
    exif.extend(struct.pack("<I", 8))
    exif.extend(struct.pack("<H", 1))
    exif.extend(struct.pack("<HHI", 0x0100, 4, 1))
    exif.extend(struct.pack("<I", 0))
    exif.extend(struct.pack("<I", 0))

    payload = b"Exif\x00\x00" + bytes(exif)
    seg_len = len(payload) + 2
    jpeg = b"\xff\xd8" + b"\xff\xe1" + seg_len.to_bytes(2, "big") + payload + b"\xff\xd9"
    assert _parse_exif_gps(jpeg) == (None, None)


def test_media_parse_exif_gps_values() -> None:
    from lockknife.modules.extraction.media import _parse_exif_gps

    exif = bytearray(b"II*\x00")
    exif.extend(struct.pack("<I", 8))
    exif.extend(struct.pack("<H", 1))
    exif.extend(struct.pack("<H", 0x8825))
    exif.extend(struct.pack("<H", 4))
    exif.extend(struct.pack("<I", 1))
    exif.extend(struct.pack("<I", 26))
    exif.extend(struct.pack("<I", 0))
    while len(exif) < 26:
        exif.append(0)

    exif.extend(struct.pack("<H", 4))

    def gps_entry(tag: int, typ: int, cnt: int, val: int) -> bytes:
        return (
            struct.pack("<H", tag)
            + struct.pack("<H", typ)
            + struct.pack("<I", cnt)
            + struct.pack("<I", val)
        )

    entries = bytearray()
    entries.extend(gps_entry(1, 2, 2, int.from_bytes(b"N\x00\x00\x00", "little")))
    entries.extend(gps_entry(2, 5, 3, 100))
    entries.extend(gps_entry(3, 2, 2, int.from_bytes(b"E\x00\x00\x00", "little")))
    entries.extend(gps_entry(4, 5, 3, 124))
    exif.extend(entries)
    exif.extend(struct.pack("<I", 0))

    while len(exif) < 100:
        exif.append(0)

    for num in (1, 2, 3):
        exif.extend(struct.pack("<I", num))
        exif.extend(struct.pack("<I", 1))

    while len(exif) < 124:
        exif.append(0)

    for num in (4, 5, 6):
        exif.extend(struct.pack("<I", num))
        exif.extend(struct.pack("<I", 1))

    payload = b"Exif\x00\x00" + bytes(exif)
    seg_len = len(payload) + 2
    jpeg = b"\xff\xd8" + b"\xff\xe1" + seg_len.to_bytes(2, "big") + payload + b"\xff\xd9"
    lat, lon = _parse_exif_gps(jpeg)
    assert lat is not None and lon is not None


def test_password_crack_rejects_algo(tmp_path) -> None:
    from lockknife.modules.credentials.password import PasswordCrackError, crack_password_with_rules

    wl = tmp_path / "w.txt"
    wl.write_text("x\n", encoding="utf-8")
    with pytest.raises(PasswordCrackError):
        crack_password_with_rules("a" * 64, "md5", wl)


def test_http_cache_expiry(monkeypatch, tmp_path) -> None:
    from lockknife.core import http as http_mod

    monkeypatch.setattr(http_mod, "_cache_root", lambda: tmp_path)
    monkeypatch.setattr(http_mod.time, "sleep", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(http_mod.time, "time", lambda: 1000.0)

    class _Resp:
        def __init__(self) -> None:
            self.status = 200

        def read(self) -> bytes:
            return b"ok"

        def getheader(self, _name: str):
            return None

    class _Conn:
        created = 0

        def __init__(self, host, timeout, context) -> None:
            _Conn.created += 1

        def request(self, method: str, path: str, headers=None, body=None) -> None:
            return None

        def getresponse(self):
            return _Resp()

        def close(self) -> None:
            return None

    monkeypatch.setattr(http_mod.http.client, "HTTPSConnection", _Conn)
    assert http_mod.http_get("https://x.test/a", cache_ttl_s=1.0) == b"ok"
    monkeypatch.setattr(http_mod.time, "time", lambda: 2000.0)
    assert http_mod.http_get("https://x.test/a", cache_ttl_s=1.0) == b"ok"
    assert _Conn.created == 2


def test_cli_readable_file_type(tmp_path) -> None:
    from lockknife.core.cli_types import READABLE_FILE

    p = tmp_path / "x.txt"
    p.write_text("x", encoding="utf-8")
    assert READABLE_FILE.convert(str(p), None, None) == p


def test_apk_decompile_and_dex_headers(tmp_path, monkeypatch) -> None:
    from lockknife.modules.apk import decompile as decomp

    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 200)

    monkeypatch.setattr(decomp, "parse_apk_manifest", lambda p: {"package": "x"})
    out_dir = tmp_path / "out"
    decomp.decompile_apk(apk, out_dir)
    assert (out_dir / "manifest.json").exists()

    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    monkeypatch.setattr(decomp, "lockknife_core", lockknife_core, raising=False)
    headers = decomp.extract_dex_headers(apk)
    assert headers[0]["file"] == "classes.dex"


def test_apk_static_analysis(monkeypatch, tmp_path) -> None:
    from lockknife.modules.apk import static_analysis as sa

    monkeypatch.setattr(
        sa,
        "parse_apk_manifest",
        lambda p: {
            "debuggable": True,
            "uses_cleartext_traffic": "true",
            "allow_backup": "true",
            "permissions": [],
        },
    )
    rows = sa.scan_apk(tmp_path / "a.apk")
    ids = {f.id for f in rows}
    assert {"debuggable", "cleartext", "allow_backup", "no_permissions"} <= ids
