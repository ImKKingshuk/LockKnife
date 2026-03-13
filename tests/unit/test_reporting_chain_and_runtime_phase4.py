import pathlib
import sys
import types

import subprocess

from lockknife.modules.reporting.chain_of_custody import (
    EvidenceItem,
    _resolved_evidence,
    build_chain_of_custody_payload,
    generate_chain_of_custody,
    sign_report_file,
    verify_chain_of_custody,
    write_chain_of_custody,
)


def test_chain_of_custody_helpers_handle_resolution_and_verification(monkeypatch, tmp_path: pathlib.Path) -> None:
    evidence_path = tmp_path / "evidence.txt"
    evidence_path.write_text("hello", encoding="utf-8")
    payload = build_chain_of_custody_payload(
        case_id="CASE-1",
        examiner="Examiner",
        notes=None,
        evidence=[EvidenceItem(name="sample", path=str(evidence_path))],
    )

    broken = [dict(payload["entries"][0], previous_hash="bad")]
    assert verify_chain_of_custody(broken)["status"] == "invalid"

    monkeypatch.setattr("lockknife.modules.reporting.chain_of_custody._sha256_file", lambda _path: (_ for _ in ()).throw(OSError("no read")))
    monkeypatch.setattr(pathlib.Path, "exists", lambda self: True)
    monkeypatch.setattr(pathlib.Path, "is_file", lambda self: True)
    monkeypatch.setattr(pathlib.Path, "stat", lambda self: (_ for _ in ()).throw(OSError("no stat")))
    resolved = _resolved_evidence(EvidenceItem(name="sample", path=str(evidence_path)))
    assert resolved.sha256 is None
    assert resolved.size_bytes is None


def test_sign_report_file_returns_unavailable_without_gpg(monkeypatch, tmp_path: pathlib.Path) -> None:
    report = tmp_path / "report.txt"
    report.write_text("hello", encoding="utf-8")
    monkeypatch.setattr("shutil.which", lambda _name: None)
    assert sign_report_file(report)["status"] == "unavailable"


def test_chain_of_custody_write_verify_and_sign_paths(monkeypatch, tmp_path: pathlib.Path) -> None:
    report = tmp_path / "report.txt"
    write_chain_of_custody("hello", report)
    assert report.read_text(encoding="utf-8") == "hello"

    payload = build_chain_of_custody_payload(
        case_id="CASE-2",
        examiner="Examiner",
        notes="n",
        evidence=[EvidenceItem(name="sample", path=str(report))],
    )
    entries = payload["entries"]
    broken_hash = [dict(entries[0], entry_hash="bad-hash")]
    rendered = generate_chain_of_custody(
        case_id="CASE-2",
        examiner="Examiner",
        notes="n",
        evidence=[EvidenceItem(name="sample", path=str(report))],
    )
    assert "Entry hash" in rendered
    assert verify_chain_of_custody(broken_hash)["reason"] == "entry-hash-mismatch"

    monkeypatch.setattr("shutil.which", lambda _name: "gpg")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: types.SimpleNamespace(returncode=1, stderr="boom"),
    )
    assert sign_report_file(report)["status"] == "error"

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: types.SimpleNamespace(returncode=0, stderr=""),
    )
    signed = sign_report_file(report, key_id="ABC123", armor=False)
    assert signed["status"] == "signed"
    assert signed["armor"] is False
    assert signed["key_id"] == "ABC123"


def test_frida_manager_handles_lookup_errors(monkeypatch) -> None:
    from lockknife.modules.runtime import frida_manager as fm_mod

    class ProcessNotFoundError(RuntimeError):
        pass

    class _Device:
        def enumerate_applications(self):
            raise ProcessNotFoundError("missing")

        def get_process(self, _app_id: str):
            raise ProcessNotFoundError("missing")

    fake_frida = types.SimpleNamespace(
        get_usb_device=lambda timeout=0: _Device(),
        get_device=lambda _id: _Device(),
        ProcessNotFoundError=ProcessNotFoundError,
    )
    monkeypatch.setitem(sys.modules, "frida", fake_frida)

    mgr = fm_mod.FridaManager()
    assert mgr.application_available("app") is False
    assert mgr.running_pid("app") is None


def test_frida_manager_describe_attach_and_load(monkeypatch) -> None:
    from lockknife.modules.runtime import frida_manager as fm_mod

    class _Script:
        def __init__(self) -> None:
            self.loaded = False

        def load(self) -> None:
            self.loaded = True

    class _Session:
        def create_script(self, _source: str) -> _Script:
            return _Script()

    class _Process:
        pid = 42

    class _Device:
        id = "usb-1"
        name = "Test Device"
        type = "usb"

        def get_process(self, _app_id: str) -> _Process:
            return _Process()

        def attach(self, _pid: int) -> _Session:
            return _Session()

    fake_frida = types.SimpleNamespace(
        get_usb_device=lambda timeout=0: _Device(),
        get_device=lambda _id: _Device(),
    )
    monkeypatch.setitem(sys.modules, "frida", fake_frida)

    mgr = fm_mod.FridaManager(device_id="usb-1")
    session_handle, session = mgr.attach_running("app")
    script = mgr.load_script(session, "send('hi');")

    assert mgr.device_id == "usb-1"
    assert mgr.describe_device()["name"] == "Test Device"
    assert session_handle.pid == 42
    assert script.loaded is True