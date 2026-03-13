import json
import pathlib

from lockknife.modules.forensics import _artifact_registry as registry_mod
from lockknife.modules.forensics._artifact_registry import iter_registered_artifacts, parse_app_data_artifacts
from lockknife.modules.forensics.parsers import (
    parse_accounts_artifacts,
    parse_app_usage_artifacts,
    parse_bluetooth_artifacts,
    parse_notifications_artifacts,
    parse_wifi_history_artifacts,
)


def test_forensics_parsers_cover_json_xml_and_text_inputs(tmp_path: pathlib.Path) -> None:
    accounts = tmp_path / "accounts.xml"
    accounts.write_text("<root><account type='google'>alice</account></root>", encoding="utf-8")
    usage = tmp_path / "usagestats.xml"
    usage.write_text("<root><package package='pkg'/><event class='MainActivity'/></root>", encoding="utf-8")
    wifi = tmp_path / "wifi_history.xml"
    wifi.write_text("<root><Network SSID='Cafe'><string name='LastConnectedTime'>123</string></Network></root>", encoding="utf-8")
    bt = tmp_path / "bt_config.conf"
    bt.write_text("address=AA:BB,name=Headset\n", encoding="utf-8")
    notifications = tmp_path / "notifications.xml"
    notifications.write_text("<root><notification title='Alert'/></root>", encoding="utf-8")
    usage_json = tmp_path / "usage.json"
    usage_json.write_text(json.dumps({"packages": [{"package": "pkg-json"}], "events": [{"class": "JsonActivity"}]}), encoding="utf-8")
    usage_list = tmp_path / "usage-list.json"
    usage_list.write_text(json.dumps([{"package": "pkg-list"}]), encoding="utf-8")
    wifi_json = tmp_path / "wifi.json"
    wifi_json.write_text(json.dumps({"networks": [{"ssid": "CafeJson"}]}), encoding="utf-8")
    wifi_list = tmp_path / "wifi-list.json"
    wifi_list.write_text(json.dumps([{"ssid": "CafeList"}]), encoding="utf-8")
    wifi_txt = tmp_path / "wifi.txt"
    wifi_txt.write_text("ssid=CafeTxt,last_connected=123\nignored\n", encoding="utf-8")

    assert parse_accounts_artifacts(accounts)[0]["name"] == "alice"
    assert parse_app_usage_artifacts(usage)[0]["_section"] == "packages"
    assert parse_app_usage_artifacts(usage_json)[1]["_section"] == "events"
    assert parse_app_usage_artifacts(usage_list)[0]["package"] == "pkg-list"
    assert parse_wifi_history_artifacts(wifi)[0]["LastConnectedTime"] == "123"
    assert parse_wifi_history_artifacts(wifi_json)[0]["ssid"] == "CafeJson"
    assert parse_wifi_history_artifacts(wifi_list)[0]["ssid"] == "CafeList"
    assert parse_wifi_history_artifacts(wifi_txt)[0]["ssid"] == "CafeTxt"
    assert parse_bluetooth_artifacts(bt)[0]["name"] == "Headset"
    assert parse_notifications_artifacts(notifications)[0]["title"] == "Alert"


def test_registry_iterates_registered_artifacts_and_app_data(tmp_path: pathlib.Path, monkeypatch) -> None:
    (tmp_path / "accounts.json").write_text(json.dumps({"accounts": [{"name": "alice"}]}), encoding="utf-8")
    (tmp_path / "settings.json").write_text(json.dumps({"theme": "dark", "count": 2}), encoding="utf-8")
    (tmp_path / "prefs.xml").write_text("<map><string name='theme'>dark</string></map>", encoding="utf-8")
    (tmp_path / "blob.pb").write_bytes(b"\x08\x01")
    (tmp_path / "broken.xml").write_text("<map>", encoding="utf-8")

    monkeypatch.setattr(registry_mod, "decode_protobuf_file", lambda path: {"source_file": str(path), "message_count": 1})

    registered = iter_registered_artifacts(tmp_path)
    app_data, protobufs = parse_app_data_artifacts(tmp_path)
    xml_preview = registry_mod._parse_app_data_file(tmp_path / "prefs.xml")
    json_preview = registry_mod._parse_app_data_file(tmp_path / "settings.json")
    assert registry_mod._records_from_payload({"items": [{"name": "alice"}]})[0]["_section"] == "items"
    assert registry_mod._records_from_payload([{"name": "bob"}])[0]["name"] == "bob"
    assert registry_mod._value_preview([1, 2]) == "list[2]"
    assert registry_mod._value_preview({"a": 1}) == "dict[1]"

    assert registered[0]["artifact_family"] == "accounts"
    assert any(item["format"] == "json" for item in app_data)
    assert any(item["format"] == "xml" for item in app_data)
    assert json_preview and json_preview["format"] == "json"
    assert xml_preview and xml_preview["format"] == "xml"
    assert protobufs[0]["message_count"] == 1