import pathlib
import sqlite3

from lockknife.core.exceptions import DeviceError
from lockknife.modules.extraction._browser_common import _sh_quote, _table_columns, _try_root_pull_file


class _Devices:
    def __init__(self, source_bytes: bytes, *, direct_pull: bool = False, cleanup_fails: bool = False, shell_fails: bool = False) -> None:
        self.source_bytes = source_bytes
        self.direct_pull = direct_pull
        self.cleanup_fails = cleanup_fails
        self.shell_fails = shell_fails
        self.shell_calls: list[str] = []
        self.pull_calls: list[str] = []

    def pull(self, _serial: str, remote: str, local: pathlib.Path, timeout_s: float = 120.0) -> None:
        self.pull_calls.append(remote)
        if self.direct_pull or remote.startswith("/sdcard/lockknife-tmp-"):
            local.write_bytes(self.source_bytes)
            return None
        raise DeviceError("permission denied")

    def shell(self, _serial: str, command: str, timeout_s: float = 20.0) -> str:
        self.shell_calls.append(command)
        if self.shell_fails and "cp " in command:
            raise DeviceError("shell failed")
        if self.cleanup_fails and "rm -f" in command:
            raise DeviceError("cleanup failed")
        return "ok"


def test_browser_common_helpers_and_root_pull(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "History"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE urls (url TEXT, title TEXT)")
        con.commit()
        assert _table_columns(con, "urls") == {"url", "title"}
    finally:
        con.close()

    assert _sh_quote("a'b") == "'a'\"'\"'b'"

    direct_local = tmp_path / "direct.bin"
    assert _try_root_pull_file(_Devices(b"abc", direct_pull=True), "SERIAL", "/data/data/file", direct_local, timeout_s=1.0) is True
    assert direct_local.read_bytes() == b"abc"

    fallback_local = tmp_path / "fallback.bin"
    devices = _Devices(b"xyz", cleanup_fails=True)
    assert _try_root_pull_file(devices, "SERIAL", "/data/data/file", fallback_local, timeout_s=1.0) is True
    assert fallback_local.read_bytes() == b"xyz"
    assert any("rm -f" in command for command in devices.shell_calls)

    failed_local = tmp_path / "failed.bin"
    assert _try_root_pull_file(_Devices(b"nope", shell_fails=True), "SERIAL", "/data/data/file", failed_local, timeout_s=1.0) is False
