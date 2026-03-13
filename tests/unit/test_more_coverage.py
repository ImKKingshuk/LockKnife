import json
import pathlib

import pytest


def test_pin_recovery_happy_path(tmp_path) -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    from lockknife.modules.credentials.pin import recover_pin

    salt = 1234
    pin = "0420"
    sha1_hex = lockknife_core.sha1_hex(f"{salt}{pin}".encode("utf-8"))

    db = tmp_path / "locksettings.db"
    import sqlite3

    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE locksettings (name TEXT, value TEXT)")
        con.execute("INSERT INTO locksettings VALUES ('lockscreen.password_salt', ?)", (str(salt),))
        con.commit()
    finally:
        con.close()

    key = tmp_path / "password.key"
    key.write_bytes(bytes.fromhex(sha1_hex) + b"\x00" * 4)

    class _Adb:
        def pull(self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0) -> None:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            if remote_path.endswith("locksettings.db"):
                local_path.write_bytes(db.read_bytes())
            else:
                local_path.write_bytes(key.read_bytes())

    class _Dev:
        _adb = _Adb()

        def pull(self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0) -> None:
            return self._adb.pull(serial, remote_path, local_path, timeout_s=timeout_s)

        def has_root(self, serial: str) -> bool:
            return True

    assert recover_pin(_Dev(), "SER", 4) == pin  # type: ignore[arg-type]


def test_parse_directory_as_aleapp(tmp_path) -> None:
    from lockknife.modules.forensics.artifacts import parse_directory_as_aleapp, parse_forensics_directory

    (tmp_path / "sms.json").write_text(json.dumps([{"a": 1}]), encoding="utf-8")
    prefs = tmp_path / "shared_prefs.xml"
    prefs.write_text("<map><string name=\"theme\">dark</string></map>", encoding="utf-8")
    out = parse_directory_as_aleapp(tmp_path)
    assert out[0].artifact_name == "Android SMS"
    report = parse_forensics_directory(tmp_path)
    assert report.summary["artifact_count"] == 1
    assert report.summary["app_data_count"] == 1


def test_pdf_report_errors_without_engines(tmp_path, monkeypatch) -> None:
    from lockknife.modules.reporting import pdf_report as pdf_mod

    monkeypatch.setattr(pdf_mod, "render_html_report", lambda *args, **kwargs: "<html></html>")
    monkeypatch.setitem(__import__("sys").modules, "weasyprint", None)
    monkeypatch.setitem(__import__("sys").modules, "xhtml2pdf", None)
    with pytest.raises(Exception):
        pdf_mod.render_pdf_report(tmp_path / "t.html", {})


def test_api_discovery_from_text(tmp_path) -> None:
    from lockknife.modules.network.api_discovery import discover_api_endpoints_from_text, extract_api_endpoints_from_pcap

    text = "GET /api/v1 HTTP/1.1\r\nHost: example.com\r\n\r\nhttps://x.test/a"
    eps = discover_api_endpoints_from_text(text, source="t")
    assert any(e.kind == "url" for e in eps)

    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(text.encode("utf-8"))
    out = extract_api_endpoints_from_pcap(pcap)
    assert out["pcap"].endswith("x.pcap")


def test_summarize_pcap_with_fake_scapy(tmp_path, monkeypatch) -> None:
    from lockknife.modules.network import api_discovery as api_mod

    class _Raw:
        def __init__(self, load: bytes) -> None:
            self.load = load

    class _Pkt:
        def __init__(self, raw: bytes, proto: str) -> None:
            self._raw = raw
            self._proto = proto

        def haslayer(self, layer) -> bool:
            name = getattr(layer, "__name__", "")
            return (name == "Raw") or (name == "TCP" and self._proto == "tcp") or (name == "UDP" and self._proto == "udp") or (name == "IP")

        def __getitem__(self, layer):
            return _Raw(self._raw)

    class IP:
        pass

    class TCP:
        pass

    class UDP:
        pass

    def rdpcap(_path: str):
        return [_Pkt(b"GET / HTTP/1.1\r\nHost: ex\r\n\r\n", "tcp"), _Pkt(b"x", "udp")]

    monkeypatch.setitem(
        __import__("sys").modules,
        "scapy.all",
        type("X", (), {"Raw": _Raw, "IP": IP, "TCP": TCP, "UDP": UDP, "rdpcap": rdpcap}),
    )
    p = tmp_path / "x.pcap"
    p.write_bytes(b"x")
    s = api_mod.summarize_pcap(p)
    assert s["total_packets"] == 2


def test_adb_validations(tmp_path) -> None:
    from lockknife.core.adb import AdbClient
    from lockknife.core.exceptions import DeviceError

    adb = AdbClient()
    with pytest.raises(DeviceError):
        adb.push("SER", tmp_path / "missing.txt", "/sdcard/x")
    with pytest.raises(DeviceError):
        adb.install("SER", tmp_path / "missing.apk")
    with pytest.raises(DeviceError):
        adb.uninstall("", "pkg")


def test_http_rejects_non_https() -> None:
    from lockknife.core.http import http_get

    with pytest.raises(Exception):
        http_get("http://example.com")
