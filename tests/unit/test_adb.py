import subprocess

import pytest

from lockknife.core.adb import AdbClient
from lockknife.core.exceptions import ExternalToolError


def test_list_devices_parses_output(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=(
                "List of devices attached\n"
                "emulator-5554\tdevice product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    adb = AdbClient(adb_path="adb")
    devices = adb.list_devices()
    assert len(devices) == 1
    assert devices[0].serial == "emulator-5554"
    assert devices[0].state == "device"
    assert devices[0].model == "sdk_gphone64_arm64"


def test_run_raises_on_nonzero_returncode(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    adb = AdbClient(adb_path="adb")
    with pytest.raises(ExternalToolError):
        adb.run(["devices"])


def test_pull_and_push_call_adb(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    adb = AdbClient(adb_path="adb")
    local = tmp_path / "a.bin"
    local.write_bytes(b"x")
    adb.push("serial1", local, "/sdcard/a.bin")
    adb.pull("serial1", "/sdcard/a.bin", tmp_path / "b.bin")

    assert any("push" in c for c in calls[0])
    assert any("pull" in c for c in calls[1])


def test_has_su_parses_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="0\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    adb = AdbClient(adb_path="adb")
    assert adb.has_su("serial1") is True
