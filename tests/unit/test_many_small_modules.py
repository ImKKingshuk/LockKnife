import pathlib
import sqlite3
import types

import pytest


def test_extract_sms_contacts_call_logs(tmp_path) -> None:
    from lockknife.modules.extraction.call_logs import extract_call_logs
    from lockknife.modules.extraction.contacts import extract_contacts
    from lockknife.modules.extraction.sms import extract_sms

    mmssms = tmp_path / "mmssms.db"
    con = sqlite3.connect(str(mmssms))
    try:
        con.execute("CREATE TABLE sms (address TEXT, body TEXT, date INTEGER, type INTEGER)")
        con.execute("INSERT INTO sms VALUES ('+1','hi',1,1)")
        con.commit()
    finally:
        con.close()

    contacts = tmp_path / "contacts2.db"
    con = sqlite3.connect(str(contacts))
    try:
        con.execute("CREATE TABLE contacts (_id INTEGER, display_name TEXT)")
        con.execute("INSERT INTO contacts VALUES (1, 'n')")
        con.commit()
    finally:
        con.close()

    calls = tmp_path / "calllog.db"
    con = sqlite3.connect(str(calls))
    try:
        con.execute(
            "CREATE TABLE calls (number TEXT, date INTEGER, duration INTEGER, type INTEGER, name TEXT)"
        )
        con.execute("INSERT INTO calls VALUES ('+1',1,2,1,'n')")
        con.commit()
    finally:
        con.close()

    class _Adb:
        def pull(
            self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0
        ) -> None:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            if remote_path.endswith("mmssms.db"):
                local_path.write_bytes(mmssms.read_bytes())
            elif remote_path.endswith("contacts2.db"):
                local_path.write_bytes(contacts.read_bytes())
            else:
                local_path.write_bytes(calls.read_bytes())

    class _Dev:
        _adb = _Adb()

        def pull(
            self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0
        ) -> None:
            return self._adb.pull(serial, remote_path, local_path, timeout_s=timeout_s)

        def has_root(self, serial: str) -> bool:
            return True

    assert extract_sms(_Dev(), "SER", limit=10)[0].body == "hi"  # type: ignore[arg-type]
    assert extract_contacts(_Dev(), "SER", limit=10)[0].display_name == "n"  # type: ignore[arg-type]
    assert extract_call_logs(_Dev(), "SER", limit=10)[0].number == "+1"  # type: ignore[arg-type]


def test_location_artifacts_parsing() -> None:
    from lockknife.modules.extraction.location import extract_location_artifacts

    class _Adb:
        def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
            if "dumpsys location" in command:
                return "provider=gps lat=1.0 lon=2.0\n"
            if "dumpsys wifi" in command:
                return "SSID: Home, BSSID: aa:bb:cc:dd:ee:ff, level: -40, frequency: 2412\n"
            return "mCellInfo=CellIdentityLte:{ mcc=310 mnc=260 tac=1 eci=2 pci=3 }\n"

    class _Dev:
        _adb = _Adb()

        def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
            return self._adb.shell(serial, command, timeout_s=timeout_s)

        def has_root(self, serial: str) -> bool:
            return True

    out = extract_location_artifacts(_Dev(), "SER")  # type: ignore[arg-type]
    assert out.snapshot.latitude == 1.0
    assert out.wifi[0].ssid == "Home"


def test_otx_indicator_classify_and_errors(monkeypatch) -> None:
    from lockknife.modules.intelligence import otx as otx_mod

    assert otx_mod.classify_indicator("192.0.2.5") == "ipv4"
    assert otx_mod.classify_indicator("a" * 64) == "sha256"
    assert otx_mod.classify_indicator("example.com") == "domain"
    assert otx_mod.classify_indicator("x") == "unknown"

    monkeypatch.delenv("OTX_API_KEY", raising=False)
    with pytest.raises(otx_mod.OtxError):
        otx_mod.get_api_key()


def test_otx_indicator_reputation_success(monkeypatch) -> None:
    from lockknife.modules.intelligence import otx as otx_mod

    class _Types:
        IPv4 = "ipv4"
        DOMAIN = "domain"
        FILE_HASH_SHA256 = "sha"

    class _OTX:
        def __init__(self, key: str) -> None:
            self._key = key

        def get_indicator_details_full(self, typ, value):
            return {"typ": typ, "value": value}

    monkeypatch.setenv("OTX_API_KEY", "k")
    monkeypatch.setitem(
        __import__("sys").modules, "OTXv2", types.SimpleNamespace(OTXv2=_OTX, IndicatorTypes=_Types)
    )
    out = otx_mod.indicator_reputation("192.0.2.5")
    assert out["typ"] == "ipv4"


def test_ioc_taxii_headers_and_load(monkeypatch) -> None:
    from lockknife.modules.intelligence import ioc as ioc_mod

    h = ioc_mod._taxii_headers(username="u", password="p")
    assert "Authorization" in h

    monkeypatch.setattr(
        ioc_mod, "http_get_json", lambda url, **kwargs: {"collections": [{"id": "c"}]}
    )
    monkeypatch.setattr(ioc_mod, "http_get", lambda url, **kwargs: b'{"objects":[]}')
    matches = ioc_mod.load_taxii_indicators("https://x", limit=1)
    assert matches == []


def test_wallet_extract_addresses_and_invalid_lookup(tmp_path) -> None:
    from lockknife.modules.crypto_wallet.wallet import (
        extract_wallet_addresses_from_sqlite,
        lookup_wallet_address,
    )

    p = tmp_path / "db.sqlite"
    p.write_text("0x" + ("a" * 40) + "\n1BoatSLRHtKNngkdXEeobR76b53LETtpyT\n", encoding="utf-8")
    out = extract_wallet_addresses_from_sqlite(p, limit=10)
    kinds = {x.kind for x in out}
    assert {"eth", "btc"} <= kinds

    lk = lookup_wallet_address("x", "unknown")
    assert lk.balance is None
