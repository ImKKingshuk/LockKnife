import pathlib
import types
import zipfile

from lockknife.modules.apk import _decompile_inspection as inspect_mod


def test_decompile_inspection_manifest_and_signing_helpers(tmp_path: pathlib.Path) -> None:
    manifest = """
    <manifest package="com.example.app" xmlns:android="http://schemas.android.com/apk/res/android">
      <application>
        <activity android:name=".MainActivity" android:exported="true">
          <intent-filter>
            <action android:name="android.intent.action.VIEW" />
            <category android:name="android.intent.category.BROWSABLE" />
            <data android:scheme="https" android:host="example.com" android:path="/open" />
          </intent-filter>
        </activity>
        <service android:name="SyncService" />
        <receiver android:name="Receiver" />
        <provider android:name="Provider" android:authorities="com.example.app.provider" />
      </application>
    </manifest>
    """.strip()

    details = inspect_mod._component_details(manifest, "com.example.app")
    assert details["summary"]["exported_total"] >= 1
    assert "https://example.com/open" in details["deeplinks"]
    assert details["activities"][0]["name"] == "com.example.app.MainActivity"
    assert inspect_mod._component_details("<manifest>", "com.example")["activities"] == []

    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"dex")
        archive.writestr("lib/arm64-v8a/libx.so", b"so")
        archive.writestr("META-INF/CERT.RSA", b"sig")
        archive.writestr("assets/config.json", '{"endpoint":"https://api.example.com","api_key":"secret-key","pin":"sha256/AAAAAAAAAAAA"}')
        archive.writestr("res/raw/hosts.txt", "direct.example.com")

    inventory = inspect_mod._archive_inventory(apk)
    assert inventory["dex_count"] == 1
    assert inventory["native_library_count"] == 1
    strings = inspect_mod._scan_archive_strings(apk)
    assert strings["stats"]["url_count"] >= 1
    assert strings["stats"]["secret_indicator_count"] >= 1
    assert strings["stats"]["certificate_pin_indicator_count"] >= 1
    assert any(item["value"] == "api.example.com" for item in strings["hosts"])

    cert = types.SimpleNamespace(
        subject="CN=Android Debug",
        issuer="CN=Android Debug",
        serial_number=123,
        signature_algorithm=types.SimpleNamespace(native="sha256WithRSAEncryption"),
        dump=lambda: b"certificate",
    )
    cert_payload = inspect_mod._certificate_payload(cert)
    assert cert_payload["is_debug_or_test"] is True
    assert cert_payload["sha256"]

    apk_obj = types.SimpleNamespace(
        get_certificates=lambda: [cert],
        is_signed_v1=lambda: True,
        is_signed_v2=lambda: False,
        is_signed_v3=lambda: True,
    )
    signing = inspect_mod._signing_summary(apk_obj, apk)
    assert signing["certificate_count"] == 1
    assert signing["schemes"]["v1"] is True


def test_decompile_inspection_misc_helpers() -> None:
    assert inspect_mod._android_attr(types.SimpleNamespace(get=lambda key: {"android:name": "Main", "name": "Fallback"}.get(key)), "name") == "Main"
    assert inspect_mod._coerce_manifest_bool("yes") is True
    assert inspect_mod._coerce_manifest_bool("off") is False
    assert inspect_mod._clean_strings([" a ", "a", "", "b"]) == ["a", "b"]
    assert inspect_mod._apk_method(types.SimpleNamespace(version=lambda: "1.0"), "version") == "1.0"
    assert inspect_mod._apk_method(types.SimpleNamespace(version=lambda x: x), "version", default="fallback") == "fallback"
    assert inspect_mod._normalize_component_name("com.example", ".Main") == "com.example.Main"
    assert inspect_mod._string_preview("x" * 120).endswith("...")
    assert inspect_mod._redact_secret("super-secret-token-value").startswith("super-")