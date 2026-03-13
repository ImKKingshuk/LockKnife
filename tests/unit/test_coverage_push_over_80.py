import os
import pathlib

import click
import pytest


def test_cli_instrumentation_group_invokes() -> None:
    from click.testing import CliRunner

    from lockknife.core.cli_instrumentation import LockKnifeGroup

    @click.group(cls=LockKnifeGroup)
    def root() -> None:
        return None

    @root.command()
    @click.option("--n", type=int, default=1)
    def ok(n: int) -> None:
        click.echo(str(n))

    runner = CliRunner()
    res = runner.invoke(root, ["ok", "--n", "2"])
    assert res.exit_code == 0
    assert "2" in res.output.splitlines()


def test_cli_types_reject_invalid_values(tmp_path) -> None:
    from lockknife.core.cli_types import ANDROID_PACKAGE, DOMAIN, HASH_HEX, IPV4, READABLE_FILE

    with pytest.raises(click.BadParameter):
        HASH_HEX.convert("zz", None, None)
    with pytest.raises(click.BadParameter):
        IPV4.convert("999.1.1.1", None, None)
    with pytest.raises(click.BadParameter):
        DOMAIN.convert("not a domain", None, None)
    with pytest.raises(click.BadParameter):
        ANDROID_PACKAGE.convert("bad/pkg", None, None)

    with pytest.raises(click.BadParameter):
        READABLE_FILE.convert(str(tmp_path / "missing.txt"), None, None)


def test_core_security_temp_and_delete(tmp_path) -> None:
    from lockknife.core.security import CryptoError, decrypt_bytes_aes256gcm, secure_delete, secure_temp_dir

    with secure_temp_dir() as d:
        mode = (d.stat().st_mode) & 0o777
        assert mode == 0o700

    f = tmp_path / "x.bin"
    f.write_bytes(b"abc")
    secure_delete(f, passes=1)
    assert not f.exists()

    with pytest.raises(ValueError):
        secure_delete(tmp_path, passes=1)

    with pytest.raises(CryptoError):
        decrypt_bytes_aes256gcm(b"k" * 32, b"nope")


def test_recovery_deleted_records_db_and_wal(tmp_path) -> None:
    from lockknife.modules.forensics.recovery import recover_deleted_records

    db = bytearray(b"SQLite format 3\x00")
    while len(db) < 100:
        db.append(0)
    db[16:18] = (4096).to_bytes(2, "big")
    db.extend(b"https://example.com/a user@example.com +123 456 7890")

    p = tmp_path / "x.db"
    p.write_bytes(bytes(db))

    wal = bytearray(b"WAL\x00")
    while len(wal) < 32:
        wal.append(0)
    wal.extend(b"\x00" * 24)
    wal.extend(b"https://wal.example/b")
    while len(wal) < 32 + 24 + 4096:
        wal.append(0)
    p.with_suffix(p.suffix + "-wal").write_bytes(bytes(wal))

    out = recover_deleted_records(p, max_fragments=10)
    texts = {f["text"] for f in out["fragments"]}
    assert "https://example.com/a" in texts
    assert "https://wal.example/b" in texts
    assert out["page_analysis"]["wal_present"] is True


def test_device_audit_expanded_checks() -> None:
    from lockknife.core.device import DeviceInfo
    from lockknife.modules.security.device_audit import run_device_audit

    class _Adb:
        def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
            if "adb_enabled" in command:
                return "1\n"
            if "development_settings_enabled" in command:
                return "1\n"
            if "install_non_market_apps" in command:
                return "1\n"
            if "package_verifier_enable" in command:
                return "0\n"
            return "\n"

    class _Dev:
        _adb = _Adb()

        def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
            return self._adb.shell(serial, command, timeout_s=timeout_s)

        def info(self, serial: str) -> DeviceInfo:
            return DeviceInfo(
                serial=serial,
                props={
                    "ro.build.tags": "test-keys",
                    "ro.build.version.sdk": "34",
                    "ro.crypto.state": "unencrypted",
                    "ro.build.version.security_patch": "2020-01-01",
                },
            )

        def has_root(self, serial: str) -> bool:
            return False

    findings = run_device_audit(_Dev(), "SER")  # type: ignore[arg-type]
    ids = {f.id for f in findings}
    assert {"test_keys", "sdk", "encryption", "security_patch", "adb_debug", "developer_options", "unknown_sources", "play_protect"} <= ids


def test_malware_scan_patterns_errors_without_extension(tmp_path, monkeypatch) -> None:
    from lockknife.modules.security.malware import MalwareScanError, scan_with_patterns

    monkeypatch.setitem(__import__("sys").modules, "lockknife.lockknife_core", None)
    t = tmp_path / "t.bin"
    t.write_bytes(b"x")
    with pytest.raises(MalwareScanError):
        scan_with_patterns(["x"], t)


def test_env_file_settings_read(monkeypatch, tmp_path) -> None:
    from lockknife.core.secrets import load_secrets

    env = tmp_path / ".env"
    env.write_text("VT_API_KEY=abc\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    s = load_secrets()
    assert s.VT_API_KEY == "abc"
