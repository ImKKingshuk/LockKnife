from lockknife.modules.credentials.wifi import _parse_wpa_supplicant


def test_parse_wpa_supplicant_basic() -> None:
    text = """
network={
    ssid="HomeWiFi"
    psk="secret"
}
""".lstrip()
    creds = _parse_wpa_supplicant(text)
    assert creds[0].ssid == "HomeWiFi"
    assert creds[0].psk == "secret"
