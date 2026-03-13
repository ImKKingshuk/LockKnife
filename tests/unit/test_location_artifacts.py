from lockknife.modules.extraction.location import _parse_cell_towers, _parse_wifi_scan


def test_parse_wifi_scan() -> None:
    raw = "SSID: Home, BSSID: aa:bb:cc:dd:ee:ff, level: -55, frequency: 2412\n"
    rows = _parse_wifi_scan(raw, limit=10)
    assert rows[0].bssid == "aa:bb:cc:dd:ee:ff"
    assert rows[0].ssid == "Home"


def test_parse_cell_towers() -> None:
    raw = "CellIdentityLte:{mMcc=310,mMnc=260,mTac=1,mEci=2,mPci=3}\n"
    rows = _parse_cell_towers(raw, limit=10)
    assert rows[0].kind == "lte"
    assert rows[0].mcc == 310
