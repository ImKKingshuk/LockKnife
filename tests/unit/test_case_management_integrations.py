import json
import pathlib
import zipfile
from dataclasses import dataclass
from types import SimpleNamespace

from click.testing import CliRunner

from tests.unit.test_case_management import _SmsRow

def test_apk_network_intel_and_passkeys_case_registration(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import apk as apk_cli
    from lockknife_headless_cli import crack as crack_cli
    from lockknife_headless_cli import intel as intel_cli
    from lockknife_headless_cli import network as network_cli
    from lockknife.core.case import create_case_workspace, load_case_manifest, register_case_artifact
    from lockknife.modules.credentials.fido2 import PasskeyArtifact
    from lockknife.modules.network.capture import CaptureResult

    runner = CliRunner()
    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-011", examiner="Examiner", title="Phase 3")
    class _Devices:
        def list_handles(self):
            from lockknife.core.device import DeviceHandle, DeviceState

            return [DeviceHandle(serial="SER-1", adb_state="device", state=DeviceState.authorized)]

        def has_root(self, _serial: str) -> bool:
            return True

    app = SimpleNamespace(devices=_Devices())

    apk_path = tmp_path / "sample.apk"
    apk_path.write_text("apk", encoding="utf-8")
    monkeypatch.setattr(apk_cli, "parse_apk_manifest", lambda *_a, **_k: {"package": "com.example.app", "permissions": []})
    monkeypatch.setattr(
        apk_cli,
        "analyze_apk",
        lambda *_a, **_k: SimpleNamespace(
            package="com.example.app",
            manifest={"package": "com.example.app", "permissions": []},
            findings=[_SmsRow("finding")],
            permission_risk={"score": 0, "risks": []},
            risk_summary={"score": 10, "level": "low"},
            mastg={"mastg_ids": []},
        ),
    )
    monkeypatch.setattr(apk_cli, "extract_dex_headers", lambda *_a, **_k: [])

    def _decompile(_apk_path: pathlib.Path, output_dir: pathlib.Path, *, mode: str = "auto") -> dict[str, str]:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "manifest.json").write_text("{}", encoding="utf-8")
        (output_dir / "decompile_report.json").write_text("{}", encoding="utf-8")
        return {
            "output_dir": str(output_dir),
            "manifest_path": str(output_dir / "manifest.json"),
            "report_path": str(output_dir / "decompile_report.json"),
            "selected_mode": mode,
        }

    monkeypatch.setattr(apk_cli, "decompile_apk_report", _decompile)

    result = runner.invoke(apk_cli.apk, ["analyze", str(apk_path), "--case-dir", str(case_dir)])
    assert result.exit_code == 0, result.output
    result = runner.invoke(apk_cli.apk, ["decompile", str(apk_path), "--case-dir", str(case_dir)])
    assert result.exit_code == 0, result.output

    pcap_path = case_dir / "evidence" / "existing_capture.pcap"
    pcap_path.write_text("pcap", encoding="utf-8")
    pcap_artifact = register_case_artifact(case_dir=case_dir, path=pcap_path, category="network-capture", source_command="network capture", device_serial="SER-1")
    monkeypatch.setattr(network_cli, "capture_pcap", lambda *_a, output_path, duration_s, iface, snaplen, **_k: (output_path.write_text("pcap", encoding="utf-8"), CaptureResult(serial="SER-1", remote_path="/sdcard/x.pcap", local_path=str(output_path), duration_s=duration_s, started_at=1.0, finished_at=2.0))[1])
    monkeypatch.setattr(network_cli, "summarize_pcap", lambda path: {"pcap": str(path), "summary": "ok"})
    monkeypatch.setattr(network_cli, "extract_api_endpoints_from_pcap", lambda path: {"pcap": str(path), "endpoints": []})

    result = runner.invoke(network_cli.network, ["capture", "-s", "SER-1", "--case-dir", str(case_dir)], obj=app)
    assert result.exit_code == 0, result.output
    result = runner.invoke(network_cli.network, ["analyze", str(pcap_path), "--case-dir", str(case_dir)])
    assert result.exit_code == 0, result.output

    ioc_input = case_dir / "evidence" / "iocs.json"
    ioc_input.write_text(json.dumps([{"ioc": "x"}]), encoding="utf-8")
    ioc_parent = register_case_artifact(case_dir=case_dir, path=ioc_input, category="analysis-input", source_command="case register")
    monkeypatch.setattr(intel_cli, "detect_iocs", lambda *_a, **_k: [_SmsRow("ioc")])

    result = runner.invoke(intel_cli.intel, ["ioc", "--input", str(ioc_input), "--case-dir", str(case_dir)])
    assert result.exit_code == 0, result.output

    def _pull_passkeys(_devices, _serial: str, *, output_dir: pathlib.Path, limit: int):
        _ = limit
        output_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = output_dir / "credential.bin"
        artifact_path.write_text("secret", encoding="utf-8")
        return [PasskeyArtifact(remote_path="/data/cred.bin", local_path=str(artifact_path), size=artifact_path.stat().st_size)]

    monkeypatch.setattr(crack_cli, "pull_passkey_artifacts", _pull_passkeys)
    result = runner.invoke(crack_cli.crack, ["passkeys", "-s", "SER-1", "--case-dir", str(case_dir)], obj=app)
    assert result.exit_code == 0, result.output

    manifest = load_case_manifest(case_dir)
    categories = {artifact.category for artifact in manifest.artifacts}
    assert "apk-analysis" in categories
    assert "apk-decompile-manifest" in categories
    assert "network-capture" in categories
    assert "network-analysis" in categories
    assert "intel-ioc" in categories
    assert "crack-passkey-artifact" in categories
    assert "crack-passkeys-manifest" in categories

    network_analysis = next(artifact for artifact in manifest.artifacts if artifact.category == "network-analysis")
    assert network_analysis.parent_artifact_ids == [pcap_artifact.artifact_id]
    intel_ioc = next(artifact for artifact in manifest.artifacts if artifact.category == "intel-ioc")
    assert intel_ioc.parent_artifact_ids == [ioc_parent.artifact_id]
    passkeys_manifest = next(artifact for artifact in manifest.artifacts if artifact.category == "crack-passkeys-manifest")
    assert passkeys_manifest.parent_artifact_ids


def test_crack_credential_workflows_register_case_artifacts(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import crack as crack_cli
    from lockknife.core.case import create_case_workspace, load_case_manifest
    from lockknife.modules.credentials.keystore import KeystoreListing
    from lockknife.modules.credentials.wifi import WifiCredential

    runner = CliRunner()
    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-012", examiner="Examiner", title="Phase 7")
    app = SimpleNamespace(devices=SimpleNamespace())

    class _Devices:
        def list_handles(self):
            from lockknife.core.device import DeviceHandle, DeviceState

            return [DeviceHandle(serial="SER-7", adb_state="device", state=DeviceState.authorized)]

        def has_root(self, _serial: str) -> bool:
            return True

    app.devices = _Devices()

    monkeypatch.setattr(
        crack_cli,
        "export_wifi_credentials",
        lambda *_a, **_k: SimpleNamespace(
            credentials=[WifiCredential(ssid="CorpWiFi", psk="secret", security="WPA2")],
            source_remote_path="/data/misc/wifi/WifiConfigStore.xml",
            source_local_path=(case_dir / "evidence" / "wifi_SER-7" / "WifiConfigStore.xml"),
            candidate_paths=["/data/misc/wifi/WifiConfigStore.xml"],
        ),
    )
    monkeypatch.setattr(crack_cli, "extract_wifi_passwords", lambda *_a, **_k: [])
    monkeypatch.setattr(
        crack_cli,
        "export_gesture_recovery",
        lambda *_a, **_k: SimpleNamespace(
            pattern="0-1-2",
            point_count=3,
            key_path=(case_dir / "evidence" / "gesture_SER-7" / "gesture.key"),
            key_size=32,
            source_remote_path="/data/system/gesture.key",
        ),
    )
    monkeypatch.setattr(crack_cli, "recover_gesture", lambda *_a, **_k: "0-1-2")
    monkeypatch.setattr(
        crack_cli,
        "inspect_keystore",
        lambda *_a, **_k: SimpleNamespace(
            listings=[KeystoreListing(path="/data/misc/keystore2", entries=["entry-1"])],
            candidate_paths=["/data/misc/keystore2"],
        ),
    )
    monkeypatch.setattr(crack_cli, "list_keystore", lambda *_a, **_k: [])
    monkeypatch.setattr(
        crack_cli,
        "export_pin_recovery",
        lambda *_a, **_k: SimpleNamespace(
            pin="123456",
            salt=99,
            password_key_sha1="ab" * 20,
            locksettings_db_path=(case_dir / "evidence" / "pin_SER-7" / "locksettings.db"),
            password_key_path=(case_dir / "evidence" / "pin_SER-7" / "password.key"),
        ),
    )
    monkeypatch.setattr(crack_cli, "recover_pin", lambda *_a, **_k: "123456")

    for rel_path in [
        case_dir / "evidence" / "wifi_SER-7" / "WifiConfigStore.xml",
        case_dir / "evidence" / "gesture_SER-7" / "gesture.key",
        case_dir / "evidence" / "pin_SER-7" / "locksettings.db",
        case_dir / "evidence" / "pin_SER-7" / "password.key",
    ]:
        rel_path.parent.mkdir(parents=True, exist_ok=True)
        rel_path.write_text("artifact", encoding="utf-8")

    assert runner.invoke(crack_cli.crack, ["wifi", "--case-dir", str(case_dir)], obj=app).exit_code == 0
    assert runner.invoke(crack_cli.crack, ["gesture", "--case-dir", str(case_dir)], obj=app).exit_code == 0
    assert runner.invoke(crack_cli.crack, ["keystore", "--case-dir", str(case_dir)], obj=app).exit_code == 0
    assert runner.invoke(crack_cli.crack, ["pin-device", "--length", "6", "--case-dir", str(case_dir)], obj=app).exit_code == 0

    manifest = load_case_manifest(case_dir)
    categories = {artifact.category for artifact in manifest.artifacts}
    assert "crack-wifi-config" in categories
    assert "crack-wifi-manifest" in categories
    assert "crack-gesture-key" in categories
    assert "crack-gesture-manifest" in categories
    assert "crack-keystore-manifest" in categories
    assert "crack-pin-locksettings" in categories
    assert "crack-pin-password-key" in categories
    assert "crack-pin-manifest" in categories

def test_runtime_and_security_case_registration(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import runtime as runtime_cli
    from lockknife_headless_cli import security as sec_cli
    from lockknife.core.case import create_case_workspace, load_case_manifest, register_case_artifact

    @dataclass
    class _Finding:
        value: str

    @dataclass
    class _Selinux:
        status: str

    @dataclass
    class _Listener:
        proto: str

    @dataclass
    class _Boot:
        unlocked: bool

    @dataclass
    class _Hardware:
        tee_present: bool

    class _Script:
        def on(self, _event: str, handler):
            handler({"type": "send", "payload": "hooked"}, None)
            return None

    class _Mgr:
        def __init__(self, device_id=None) -> None:
            self.device_id = device_id

        def spawn_and_attach(self, app_id: str):
            return SimpleNamespace(pid=42, app_id=app_id), object()

        def load_script(self, _session, _script: str):
            return _Script()

    runner = CliRunner()
    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-012", examiner="Examiner", title="Runtime Security")
    app = SimpleNamespace(devices=SimpleNamespace())

    script_path = tmp_path / "hook.js"
    script_path.write_text("send('ok')", encoding="utf-8")
    monkeypatch.setattr(runtime_cli, "FridaManager", _Mgr)
    monkeypatch.setattr(runtime_cli, "ssl_pinning_bypass_script", lambda *_a, **_k: "ssl")
    monkeypatch.setattr(runtime_cli, "method_tracer_script", lambda *_a, **_k: "trace")
    monkeypatch.setattr(runtime_cli, "memory_search", lambda *_a, **_k: json.dumps({"hits": ["0x1"], "pattern": "abc"}))
    monkeypatch.setattr(runtime_cli, "heap_dump", lambda *_a, **_k: json.dumps({"ok": True, "output_path": "/sdcard/heap.hprof"}))
    monkeypatch.setattr(runtime_cli.time, "sleep", lambda *_a, **_k: (_ for _ in ()).throw(KeyboardInterrupt()))

    for args in (
        ["hook", "app", "--script", str(script_path), "--case-dir", str(case_dir)],
        ["bypass-ssl", "app", "--case-dir", str(case_dir)],
        ["trace", "app", "--class", "Clazz", "--method", "m", "--case-dir", str(case_dir)],
        ["memory-search", "app", "--pattern", "abc", "--case-dir", str(case_dir)],
        ["heap-dump", "app", "--case-dir", str(case_dir)],
    ):
        result = runner.invoke(runtime_cli.runtime, args, obj=app)
        assert result.exit_code == 0, result.output

    target = case_dir / "evidence" / "target.bin"
    target.write_text("target", encoding="utf-8")
    target_artifact = register_case_artifact(case_dir=case_dir, path=target, category="evidence-file", source_command="case register")
    mastg_input = case_dir / "derived" / "artifacts.json"
    mastg_input.write_text(json.dumps([{"id": "x"}]), encoding="utf-8")
    mastg_artifact = register_case_artifact(case_dir=case_dir, path=mastg_input, category="analysis-input", source_command="case register")

    monkeypatch.setattr(sec_cli, "run_device_audit", lambda *_a, **_k: [_Finding("issue")])
    monkeypatch.setattr(sec_cli, "get_selinux_status", lambda *_a, **_k: _Selinux("enforcing"))
    monkeypatch.setattr(sec_cli, "scan_with_yara", lambda *_a, **_k: [_Finding("malware")])
    monkeypatch.setattr(sec_cli, "scan_network", lambda *_a, **_k: SimpleNamespace(dns=["192.0.2.4"], dns_cache=[], listening=[_Listener("tcp")], raw="ok"))
    monkeypatch.setattr(sec_cli, "analyze_bootloader", lambda *_a, **_k: _Boot(False))
    monkeypatch.setattr(sec_cli, "analyze_hardware_security", lambda *_a, **_k: _Hardware(True))
    monkeypatch.setattr(sec_cli, "mastg_summary", lambda *_a, **_k: {"items": [{"id": "x"}]})

    for args in (
        ["scan", "-s", "SER-1", "--case-dir", str(case_dir)],
        ["selinux", "-s", "SER-1", "--case-dir", str(case_dir)],
        ["malware", "--yara", str(script_path), "--target", str(target), "--case-dir", str(case_dir)],
        ["network-scan", "-s", "SER-1", "--case-dir", str(case_dir)],
        ["bootloader", "-s", "SER-1", "--case-dir", str(case_dir)],
        ["hardware", "-s", "SER-1", "--case-dir", str(case_dir)],
        ["owasp", "--artifacts", str(mastg_input), "--case-dir", str(case_dir)],
    ):
        result = runner.invoke(sec_cli.security, args, obj=app)
        assert result.exit_code == 0, result.output

    manifest = load_case_manifest(case_dir)
    categories = {artifact.category for artifact in manifest.artifacts}
    assert {"runtime-script", "runtime-session-log", "runtime-session", "runtime-memory-search", "runtime-heap-dump"} <= categories
    assert {
        "security-scan",
        "security-selinux",
        "security-malware",
        "security-network-scan",
        "security-bootloader",
        "security-hardware",
        "security-owasp",
    } <= categories

    security_malware = next(artifact for artifact in manifest.artifacts if artifact.category == "security-malware")
    assert target_artifact.artifact_id in security_malware.parent_artifact_ids
    security_owasp = next(artifact for artifact in manifest.artifacts if artifact.category == "security-owasp")
    assert security_owasp.parent_artifact_ids == [mastg_artifact.artifact_id]
    runtime_session = next(artifact for artifact in manifest.artifacts if artifact.category == "runtime-session")
    assert runtime_session.parent_artifact_ids

def test_ai_and_crypto_case_registration(monkeypatch, tmp_path: pathlib.Path) -> None:
    from lockknife_headless_cli import ai as ai_cli
    from lockknife_headless_cli import crypto_wallet as crypto_cli
    from lockknife.core.case import create_case_workspace, load_case_manifest, register_case_artifact

    runner = CliRunner()
    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-013", examiner="Examiner", title="AI Crypto")

    features = case_dir / "evidence" / "features.json"
    features.write_text(json.dumps([{"f1": 1, "label": 0}]), encoding="utf-8")
    features_artifact = register_case_artifact(case_dir=case_dir, path=features, category="analysis-input", source_command="case register")

    corpus = case_dir / "evidence" / "corpus.txt"
    corpus.write_text("secret\npassword\n", encoding="utf-8")
    corpus_artifact = register_case_artifact(case_dir=case_dir, path=corpus, category="wordlist", source_command="case register")

    wallet_db = case_dir / "evidence" / "wallet.db"
    wallet_db.write_text("wallet", encoding="utf-8")
    wallet_artifact = register_case_artifact(case_dir=case_dir, path=wallet_db, category="wallet-db", source_command="case register")

    monkeypatch.setattr(ai_cli, "anomaly_scores", lambda *_a, **_k: [{"row": {"f1": 1}, "anomaly_score": 0.1}])

    def _train(rows, features_arg, label_key, model_path):
        _ = (rows, features_arg, label_key)
        model_path.write_text("model", encoding="utf-8")
        return model_path

    monkeypatch.setattr(ai_cli, "train_classifier", _train)
    monkeypatch.setattr(ai_cli, "predict_classifier", lambda *_a, **_k: [{"row": {"f1": 1}, "prediction": 1}])
    monkeypatch.setattr(ai_cli, "PasswordPredictor", SimpleNamespace(train_from_wordlist=lambda *_a, **_k: SimpleNamespace(generate=lambda **_kw: ["pw1", "pw2"])))
    monkeypatch.setattr(crypto_cli, "extract_wallet_addresses_from_sqlite", lambda *_a, **_k: [_SmsRow("addr")])
    monkeypatch.setattr(crypto_cli, "enrich_wallet_addresses", lambda *_a, **_k: [{"address": "addr", "lookup": {}}])

    result = runner.invoke(ai_cli.ai, ["anomaly", "--input", str(features), "--feature", "f1", "--case-dir", str(case_dir)])
    assert result.exit_code == 0, result.output

    result = runner.invoke(ai_cli.ai, ["train-malware", "--input", str(features), "--feature", "f1", "--label", "label", "--case-dir", str(case_dir)])
    assert result.exit_code == 0, result.output
    model_path = case_dir / "derived" / "ai_malware_model_features.joblib"
    assert model_path.exists()

    result = runner.invoke(ai_cli.ai, ["classify-malware", "--input", str(features), "--model", str(model_path), "--case-dir", str(case_dir)])
    assert result.exit_code == 0, result.output

    result = runner.invoke(ai_cli.ai, ["predict-password", "--corpus", str(corpus), "--count", "2", "--case-dir", str(case_dir)])
    assert result.exit_code == 0, result.output

    result = runner.invoke(crypto_cli.crypto_wallet, ["wallet", str(wallet_db), "--lookup", "--case-dir", str(case_dir)])
    assert result.exit_code == 0, result.output

    manifest = load_case_manifest(case_dir)
    categories = {artifact.category for artifact in manifest.artifacts}
    assert {"ai-anomaly", "ai-malware-model", "ai-malware-classification", "ai-password-predictions", "crypto-wallet"} <= categories

    ai_anomaly = next(artifact for artifact in manifest.artifacts if artifact.category == "ai-anomaly")
    assert ai_anomaly.parent_artifact_ids == [features_artifact.artifact_id]
    ai_model = next(artifact for artifact in manifest.artifacts if artifact.category == "ai-malware-model")
    assert ai_model.parent_artifact_ids == [features_artifact.artifact_id]
    ai_classification = next(artifact for artifact in manifest.artifacts if artifact.category == "ai-malware-classification")
    assert features_artifact.artifact_id in ai_classification.parent_artifact_ids
    assert ai_model.artifact_id in ai_classification.parent_artifact_ids
    ai_passwords = next(artifact for artifact in manifest.artifacts if artifact.category == "ai-password-predictions")
    assert ai_passwords.parent_artifact_ids == [corpus_artifact.artifact_id]
    wallet_output = next(artifact for artifact in manifest.artifacts if artifact.category == "crypto-wallet")
    assert wallet_output.parent_artifact_ids == [wallet_artifact.artifact_id]
