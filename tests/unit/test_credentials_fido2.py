import pathlib

import pytest

from lockknife.core.exceptions import DeviceError
from lockknife.modules.credentials.fido2 import find_passkey_artifacts, pull_passkey_artifacts


class _FakeAdb:
    def __init__(self) -> None:
        self.shell_cmds: list[str] = []

    def shell(self, serial: str, cmd: str, timeout_s: float = 0.0) -> str:
        self.shell_cmds.append(cmd)
        if "find /data" in cmd:
            return "/data/data/com.example/fido_db\n"
        return ""

    def pull(self, serial: str, remote: str, local: pathlib.Path, timeout_s: float = 0.0) -> None:
        local.write_bytes(b"artifact")


class _FakeDevices:
    def __init__(self, *, root: bool) -> None:
        self._adb = _FakeAdb()
        self._root = root

    def shell(self, serial: str, cmd: str, timeout_s: float = 0.0) -> str:
        return self._adb.shell(serial, cmd, timeout_s=timeout_s)

    def pull(self, serial: str, remote: str, local: pathlib.Path, timeout_s: float = 0.0) -> None:
        return self._adb.pull(serial, remote, local, timeout_s=timeout_s)

    def has_root(self, serial: str) -> bool:
        return bool(self._root)


def test_find_passkey_artifacts_requires_root() -> None:
    devices = _FakeDevices(root=False)
    with pytest.raises(DeviceError):
        find_passkey_artifacts(devices, "SERIAL")  # type: ignore[arg-type]


def test_pull_passkey_artifacts_writes_files(tmp_path: pathlib.Path) -> None:
    devices = _FakeDevices(root=True)
    out_dir = tmp_path / "passkeys"
    rows = pull_passkey_artifacts(devices, "SERIAL", output_dir=out_dir, limit=10)  # type: ignore[arg-type]
    assert len(rows) == 1
    assert rows[0].local_path is not None
    p = pathlib.Path(rows[0].local_path)
    assert p.exists()
    assert p.read_bytes() == b"artifact"
