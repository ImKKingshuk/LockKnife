import pathlib

import pytest


def test_adb_list_devices_parses(monkeypatch) -> None:
    from lockknife.core.adb import AdbClient

    class _P:
        def __init__(self, rc: int, out: str, err: str = "") -> None:
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    def fake_run(args, check, capture_output, text, timeout):
        assert args[0] == "adb"
        if args[1:3] == ["devices", "-l"]:
            return _P(
                0,
                "List of devices attached\n"
                "SERIAL1 device product:sdk_gphone model:Pixel transport_id:1\n"
                "SERIAL2 unauthorized transport_id:2\n",
            )
        if args[1:3] == ["-s", "SERIAL1"] and args[3] == "shell":
            return _P(0, "[ro.build.version.sdk]: [34]\n")
        return _P(1, "", "fail")

    monkeypatch.setattr("subprocess.run", fake_run)
    adb = AdbClient()
    devs = adb.list_devices()
    assert devs[0].serial == "SERIAL1"
    assert devs[0].model == "Pixel"
    assert devs[1].state == "unauthorized"
    assert adb.getprop("SERIAL1")["ro.build.version.sdk"] == "34"


def test_adb_list_devices_skips_noise(monkeypatch) -> None:
    from lockknife.core.adb import AdbClient

    class _P:
        def __init__(self, out: str) -> None:
            self.returncode = 0
            self.stdout = out
            self.stderr = ""

    def fake_run(args, check, capture_output, text, timeout):
        if args[1:3] == ["devices", "-l"]:
            return _P("List of devices attached\n* daemon started successfully\njunk\nSERIAL device model:X foo\n")
        if args[3] == "shell":
            return _P("[k]: [v]\nnot-a-prop\n")
        return _P("")

    monkeypatch.setattr("subprocess.run", fake_run)
    adb = AdbClient(adb_path="adb")
    assert adb.adb_path == "adb"
    devs = adb.list_devices()
    assert devs[0].model == "X"
    props = adb.getprop("SERIAL")
    assert props["k"] == "v"


def test_adb_shell_requires_serial() -> None:
    from lockknife.core.adb import AdbClient
    from lockknife.core.exceptions import DeviceError

    with pytest.raises(DeviceError):
        AdbClient().shell("", "id")

    with pytest.raises(DeviceError):
        AdbClient().pull("", "/sdcard/x", pathlib.Path("x"))

    with pytest.raises(DeviceError):
        AdbClient().push("", pathlib.Path("x"), "/sdcard/x")

    with pytest.raises(DeviceError):
        AdbClient().install("", pathlib.Path("x.apk"))


def test_adb_run_errors(monkeypatch) -> None:
    from lockknife.core.adb import AdbClient
    from lockknife.core.exceptions import ExternalToolError
    import subprocess

    def raise_fnf(*args, **kwargs):
        raise FileNotFoundError("adb")

    monkeypatch.setattr(subprocess, "run", raise_fnf)
    with pytest.raises(ExternalToolError):
        AdbClient(adb_path="missing-adb").run(["devices"])

    def raise_to(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="adb", timeout=1.0)

    monkeypatch.setattr(subprocess, "run", raise_to)
    with pytest.raises(ExternalToolError):
        AdbClient().run(["devices"], timeout_s=0.01)


def test_adb_install_uninstall_flags(monkeypatch, tmp_path) -> None:
    from lockknife.core.adb import AdbClient

    called: list[list[str]] = []

    class _P:
        def __init__(self) -> None:
            self.returncode = 0
            self.stdout = "ok\n"
            self.stderr = ""

    def fake_run(args, check, capture_output, text, timeout):
        called.append(args)
        return _P()

    monkeypatch.setattr("subprocess.run", fake_run)
    adb = AdbClient()
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    adb.install("SER", apk, replace=False)
    adb.uninstall("SER", "pkg", keep_data=True)
    assert any("install" in a for a in called)
    assert any("-k" in a for a in called)


def test_device_manager_map_devices_collects_exceptions() -> None:
    from lockknife.core.adb import AdbDevice
    from lockknife.core.device import DeviceManager

    class _Adb:
        def list_devices(self):
            return [AdbDevice(serial="a", state="device"), AdbDevice(serial="b", state="offline")]

        def connect(self, host: str):
            return f"connected {host}"

        def getprop(self, serial: str):
            return {"ro.build.version.sdk": "34"}

        def has_su(self, serial: str):
            return serial == "a"

    mgr = DeviceManager(_Adb())  # type: ignore[arg-type]
    handles = mgr.list_handles()
    assert {h.serial for h in handles} == {"a", "b"}
    assert mgr.authorized_serials() == ["a"]
    assert mgr.has_root("a") is True
    assert mgr.info("a").props["ro.build.version.sdk"] == "34"

    def f(s: str) -> int:
        if s == "b":
            raise RuntimeError("nope")
        return 1

    res = mgr.map_devices(f)
    assert res["a"] == 1
    assert isinstance(res["b"], Exception)

    assert mgr.get_state("a").name == "authorized"
    assert mgr.get_state("missing").name == "disconnected"

    out = mgr.connect_device("192.0.2.2:5555")
    assert "connected" in out
    assert mgr.get_state("192.0.2.2:5555").name == "connected"


def test_adb_connect_disconnect_pull_success(monkeypatch, tmp_path) -> None:
    from lockknife.core.adb import AdbClient

    class _P:
        def __init__(self, out: str = "") -> None:
            self.returncode = 0
            self.stdout = out
            self.stderr = ""

    def fake_run(args, check, capture_output, text, timeout):
        if args[1] == "connect":
            return _P("connected\n")
        if args[1] == "-s" and args[3] == "pull":
            return _P("ok\n")
        return _P("")

    monkeypatch.setattr("subprocess.run", fake_run)
    adb = AdbClient()
    assert "connected" in adb.connect("192.0.2.1:5555")
    lp = tmp_path / "x.bin"
    adb.pull("SER", "/sdcard/x", lp)
