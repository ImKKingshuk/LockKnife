import dataclasses
import json
import pathlib
import sys
from types import SimpleNamespace

from click.testing import CliRunner


def _invoke(cmd, args, obj=None):
    runner = CliRunner()
    result = runner.invoke(cmd, args, obj=obj)
    assert result.exit_code == 0, result.output


@dataclasses.dataclass
class _Row:
    value: str


@dataclasses.dataclass
class _Artifact:
    name: str
    records: list[dict]


@dataclasses.dataclass
class _Wifi:
    ssid: str
    psk: str | None


@dataclasses.dataclass
class _Keystore:
    path: str
    entries: list[str]


@dataclasses.dataclass
class _Passkey:
    rp_id: str
    user_name: str


def test_cli_analyze_evidence(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import analyze as analyze_cli

    monkeypatch.setattr(
        analyze_cli,
        "parse_directory_as_aleapp",
        lambda *_a, **_k: [_Artifact(name="a", records=[{"ioc": "x"}])],
    )
    monkeypatch.setattr(analyze_cli, "detect_iocs", lambda *_a, **_k: [_Row("ioc")])
    monkeypatch.setattr(analyze_cli, "scan_with_patterns", lambda *_a, **_k: ["hit"])

    dex = tmp_path / "a.dex"
    dex.write_text("dex", encoding="utf-8")
    _invoke(analyze_cli.analyze, ["evidence", "--dir", str(tmp_path), "--pattern", "deadbeef"])


def test_cli_completion() -> None:
    from lockknife_headless_cli import completion as completion_cli

    _invoke(completion_cli.completion, ["bash"])


def test_cli_crack_commands(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import crack as crack_cli

    class _Core:
        @staticmethod
        def bruteforce_numeric_pin(_h, _algo, _len):
            return "1234"

        @staticmethod
        def dictionary_attack(_h, _algo, _wl):
            return "pass"

    import lockknife

    monkeypatch.setitem(sys.modules, "lockknife.lockknife_core", _Core())
    monkeypatch.setattr(lockknife, "lockknife_core", _Core(), raising=False)

    class _Devices:
        def list_handles(self):
            from lockknife.core.device import DeviceHandle, DeviceState

            return [DeviceHandle(serial="S", adb_state="device", state=DeviceState.authorized)]

        def has_root(self, _serial: str) -> bool:
            return True

    app = SimpleNamespace(devices=_Devices())

    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("pass", encoding="utf-8")

    monkeypatch.setattr(crack_cli, "crack_password_with_rules", lambda *_a, **_k: "pass1")
    monkeypatch.setattr(crack_cli, "recover_gesture", lambda *_a, **_k: "1-2-3-4")
    monkeypatch.setattr(crack_cli, "recover_pin", lambda *_a, **_k: "0000")
    monkeypatch.setattr(crack_cli, "extract_wifi_passwords", lambda *_a, **_k: [_Wifi("ssid", "psk")])
    monkeypatch.setattr(crack_cli, "list_keystore", lambda *_a, **_k: [_Keystore("/data", ["k1"])])
    monkeypatch.setattr(crack_cli, "pull_passkey_artifacts", lambda *_a, **_k: [_Passkey("rp", "user")])

    _invoke(crack_cli.crack, ["pin", "--hash", "0" * 64, "--algo", "sha256", "--length", "4"])
    _invoke(crack_cli.crack, ["password", "--hash", "0" * 64, "--algo", "sha256", "--wordlist", str(wordlist)])
    _invoke(crack_cli.crack, ["password-rules", "--hash", "0" * 64, "--algo", "sha256", "--wordlist", str(wordlist), "--max-suffix", "1"])
    _invoke(crack_cli.crack, ["gesture", "-s", "S"], obj=app)
    _invoke(crack_cli.crack, ["pin-device", "-s", "S", "--length", "4"], obj=app)
    _invoke(crack_cli.crack, ["wifi", "-s", "S"], obj=app)
    _invoke(crack_cli.crack, ["keystore", "-s", "S"], obj=app)
    _invoke(crack_cli.crack, ["passkeys", "-s", "S", "--output-dir", str(tmp_path), "--limit", "1"], obj=app)


def test_cli_intel_reputation(monkeypatch) -> None:
    from lockknife_headless_cli import intel as intel_cli

    monkeypatch.setattr(
        intel_cli,
        "file_report",
        lambda *_a, **_k: {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 1}}},
    )
    monkeypatch.setattr(intel_cli, "indicator_reputation", lambda *_a, **_k: {"ok": True})
    monkeypatch.setattr(intel_cli, "correlate_cves_for_apk_package", lambda *_a, **_k: {"cves": []})

    _invoke(
        intel_cli.intel,
        [
            "reputation",
            "--hash",
            "0" * 64,
            "--domain",
            "example.com",
            "--ip",
            "192.0.2.5",
            "--package",
            "com.example.app",
        ],
    )
