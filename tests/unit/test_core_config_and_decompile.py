import pathlib
import subprocess
import types
import zipfile

import pytest


def test_load_config_override_missing(monkeypatch, tmp_path) -> None:
    from lockknife.core.config import ConfigError, load_config

    monkeypatch.setenv("LOCKKNIFE_CONFIG", str(tmp_path / "missing.toml"))
    with pytest.raises(ConfigError):
        load_config()


def test_load_config_toml_and_legacy(monkeypatch, tmp_path) -> None:
    from lockknife.core.config import load_config

    monkeypatch.delenv("LOCKKNIFE_CONFIG", raising=False)

    toml = tmp_path / "lockknife.toml"
    toml.write_text("[lockknife]\nlog_level='DEBUG'\n", encoding="utf-8")
    monkeypatch.setattr(pathlib.Path, "cwd", lambda: tmp_path)
    cfg = load_config()
    assert cfg.config.log_level == "DEBUG"
    assert cfg.path == toml

    toml.unlink()
    legacy = tmp_path / "lockknife.conf"
    legacy.write_text("loglevel=WARNING\nadb=/usr/bin/adb\n", encoding="utf-8")
    cfg2 = load_config()
    assert cfg2.config.log_level == "WARNING"


def test_apk_require_androguard_error(monkeypatch, tmp_path) -> None:
    from lockknife.modules.apk.decompile import ApkError, parse_apk_manifest

    monkeypatch.setitem(__import__("sys").modules, "androguard", None)
    with pytest.raises(ApkError):
        parse_apk_manifest(tmp_path / "a.apk")


def test_apk_parse_manifest_with_stub(monkeypatch, tmp_path) -> None:
    from lockknife.modules.apk import decompile as decomp

    class _Cert:
        subject = "CN=Android Debug,O=Android"
        issuer = "CN=Android Debug,O=Android"
        serial_number = 42
        signature_algorithm = "sha256WithRSAEncryption"

        def dump(self) -> bytes:
            return b"cert-bytes"

    class _APK:
        def __init__(self, path: str) -> None:
            self._path = path

        def get_android_manifest_xml(self):
            return types.SimpleNamespace(
                toxml=lambda: (
                    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                    'package="com.example">'
                    '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>'
                    '<application android:allowBackup="true" '
                    'android:usesCleartextTraffic="true" '
                    'android:networkSecurityConfig="@xml/netsec">'
                    '<activity android:name=".MainActivity">'
                    '<intent-filter android:autoVerify="true">'
                    '<action android:name="android.intent.action.VIEW"/>'
                    '<category android:name="android.intent.category.BROWSABLE"/>'
                    '<data android:scheme="https" android:host="example.com" android:pathPrefix="/open"/>'
                    '</intent-filter>'
                    '</activity>'
                    '<provider android:name=".Provider" android:authorities="com.example.provider" android:exported="true"/>'
                    '</application>'
                    '</manifest>'
                )
            )

        def get_package(self):
            return "com.example"

        def get_androidversion_name(self):
            return "1"

        def get_androidversion_code(self):
            return "2"

        def get_permissions(self):
            return ["a", "a", "b"]

        def get_app_name(self):
            return "Example"

        def get_main_activity(self):
            return ".MainActivity"

        def get_min_sdk_version(self):
            return "24"

        def get_target_sdk_version(self):
            return "33"

        def get_max_sdk_version(self):
            return None

        def get_features(self):
            return ["android.hardware.camera"]

        def get_libraries(self):
            return ["libssl"]

        def get_details_permissions(self):
            return {"a": ["dangerous"]}

        def get_activities(self):
            return ["A"]

        def get_services(self):
            return []

        def get_receivers(self):
            return []

        def get_providers(self):
            return []

        def is_debuggable(self):
            return True

        def get_certificates(self):
            return [_Cert()]

        def is_signed_v1(self):
            return True

        def is_signed_v2(self):
            return False

        def is_signed_v3(self):
            return False

        def get_element(self, *_args, **_kwargs):
            return None

    monkeypatch.setitem(
        __import__("sys").modules,
        "androguard.core.bytecodes.apk",
        types.SimpleNamespace(APK=_APK),
    )
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
        archive.writestr(
            "classes.dex",
            b"const-string https://example.com api_key=ABCDEF123456 okhttp3 addJavascriptInterface appsflyer",
        )
    info = decomp.parse_apk_manifest(apk)
    assert info["package"] == "com.example"
    assert info["app_name"] == "Example"
    assert info["sdk"]["target"] == "33"
    assert info["archive"]["dex_count"] == 1
    assert info["string_analysis"]["stats"]["url_count"] >= 1
    assert info["string_analysis"]["stats"]["tracker_count"] >= 1
    assert info["string_analysis"]["stats"]["library_count"] >= 1
    assert info["string_analysis"]["stats"]["code_signal_count"] >= 1
    assert info["components"]["summary"]["exported_total"] >= 2
    assert info["components"]["summary"]["browsable_deeplink_total"] == 1
    assert info["component_interactions"]["provider_authority_map"]["com.example.provider"] == ["com.example.Provider"]
    assert info["component_interactions"]["custom_schemes"] == []
    assert info["components"]["deeplinks"][0]["uri"] == "https://example.com/open"
    assert info["manifest_flags"]["allow_backup"] is True
    assert info["signing"]["strict_verification"]["status"] == "warn"
    assert info["signing"]["has_debug_or_test_certificate"] is True


def test_decompile_apk_report_runs_selected_pipeline(monkeypatch, tmp_path) -> None:
    from lockknife.modules.apk import decompile as decomp
    from lockknife.modules.apk import _decompile_tools as decomp_tools

    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")

    monkeypatch.setattr(
        decomp,
        "parse_apk_manifest",
        lambda _path: {
            "package": "pkg",
            "archive": {"dex_count": 0},
            "component_summary": {},
            "signing": {},
            "string_analysis": {},
        },
    )
    monkeypatch.setattr(
        decomp_tools.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in {"apktool", "jadx"} else None,
    )
    commands: list[list[str]] = []

    def _run(command, check, capture_output, text):
        commands.append(command)
        pathlib.Path(command[2]).mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(decomp_tools.subprocess, "run", _run)

    report = decomp.decompile_apk_report(apk, tmp_path / "out", mode="jadx")

    assert report["selected_mode"] == "jadx"
    assert report["decompile_outputs"]["jadx"].endswith("/out/jadx")
    assert report["pipelines"][0]["name"] == "jadx"
    assert report["decompilation_depth"]["reconstructed_sources"] is True
    assert pathlib.Path(report["report_path"]).exists()
    assert commands == [["jadx", "-d", str(tmp_path / "out" / "jadx"), str(apk)]]


def test_decompile_auto_prefers_jadx_and_reports_depth_when_tools_exist(monkeypatch) -> None:
    from lockknife.modules.apk import _decompile_tools as decomp_tools

    monkeypatch.setattr(
        decomp_tools.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in {"apktool", "jadx"} else None,
    )

    tools = decomp_tools.available_decompile_tools()

    assert decomp_tools.selected_decompile_mode("auto", tools) == "jadx"
    assert decomp_tools.decompile_positioning("jadx", tools)["source_recovery_level"] == "java-like-source"
    assert decomp_tools._decompilation_depth("jadx")["reconstructed_sources"] is True


def test_decompile_auto_falls_back_when_jadx_fails(monkeypatch, tmp_path) -> None:
    from lockknife.modules.apk import _decompile_tools as decomp_tools

    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")

    monkeypatch.setattr(
        decomp_tools.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in {"apktool", "jadx"} else None,
    )

    def _run(command, check, capture_output, text):
        if command[0] == "jadx":
            raise subprocess.CalledProcessError(1, command, output="", stderr="boom")
        pathlib.Path(command[4]).mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(decomp_tools.subprocess, "run", _run)

    report = decomp_tools.run_decompile_pipeline(apk, tmp_path / "out", requested_mode="auto")

    assert report["selected_mode"] == "jadx"
    assert report["effective_mode"] == "apktool"
    assert report["fallback_applied"] is True
    assert report["source_inventory"]["root"].endswith("/apktool")


def test_selected_decompile_mode_validates_missing_tools() -> None:
    from lockknife.modules.apk import _decompile_tools as decomp_tools
    from lockknife.modules.apk._decompile_shared import ApkError

    tools = {
        "unpack": {"available": True, "path": None},
        "apktool": {"available": False, "path": None},
        "jadx": {"available": False, "path": None},
    }

    with pytest.raises(ApkError):
        decomp_tools.selected_decompile_mode("apktool", tools)
    with pytest.raises(ApkError):
        decomp_tools.selected_decompile_mode("hybrid", tools)
    with pytest.raises(ApkError):
        decomp_tools.selected_decompile_mode("nope", tools)


def test_decompile_auto_falls_back_to_unpack_when_no_tools(monkeypatch, tmp_path) -> None:
    from lockknife.modules.apk import _decompile_tools as decomp_tools

    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
        archive.writestr("classes.dex", b"dex")

    monkeypatch.setattr(decomp_tools.shutil, "which", lambda _name: None)
    report = decomp_tools.run_decompile_pipeline(apk, tmp_path / "out", requested_mode="auto")

    assert report["selected_mode"] == "unpack"
    assert report["effective_mode"] == "unpack"
    assert report["source_inventory"]["file_count"] >= 1


def test_run_external_stage_raises_apk_error(monkeypatch, tmp_path) -> None:
    from lockknife.modules.apk import _decompile_tools as decomp_tools
    from lockknife.modules.apk._decompile_shared import ApkError

    monkeypatch.setattr(
        decomp_tools.subprocess,
        "run",
        lambda command, **_kwargs: (_ for _ in ()).throw(subprocess.CalledProcessError(1, command, stderr="failed")),
    )

    with pytest.raises(ApkError, match="failed"):
        decomp_tools._run_external_stage("jadx", ["jadx", "-d", str(tmp_path), "sample.apk"], tmp_path)


def test_build_source_inventory_counts_interesting_files(tmp_path) -> None:
    from lockknife.modules.apk import _decompile_tools as decomp_tools

    root = tmp_path / "scan"
    (root / "src").mkdir(parents=True)
    (root / "src" / "Main.java").write_text("class Main {}", encoding="utf-8")
    (root / "src" / "Main.kt").write_text("class Main", encoding="utf-8")
    (root / "res.xml").write_text("<r/>", encoding="utf-8")
    (root / "AndroidManifest.json").write_text("{}", encoding="utf-8")
    (root / "classes.smali").write_text(".class public Lx;", encoding="utf-8")

    inventory = decomp_tools._build_source_inventory(tmp_path, {"jadx": str(root)}, "jadx")

    assert inventory["java_like_count"] == 2
    assert inventory["counts"]["smali"] == 1
    assert "src/Main.java" in inventory["interesting_files"]
