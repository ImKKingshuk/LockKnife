from __future__ import annotations

import pathlib
import sqlite3
from unittest.mock import MagicMock

from click.testing import CliRunner

from lockknife.core.device import DeviceHandle, DeviceManager, DeviceState
from lockknife.modules.credentials.fido2 import (
    PASSKEY_CANDIDATE_PATHS,
    PasskeyArtifact,
    find_passkey_artifacts,
    parse_passkey_database,
    pull_passkey_artifacts,
)
from lockknife_headless_cli.crack import crack


def test_parse_passkey_database_fido_credentials(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "fido2.db"
    conn = sqlite3.connect(str(db))
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE fido_credentials (
            id TEXT PRIMARY KEY,
            rp_id TEXT NOT NULL,
            user_name TEXT,
            display_name TEXT,
            credential_id TEXT NOT NULL,
            created_time INTEGER,
            last_used_time INTEGER
        )
        """
    )
    cur.execute(
        """
        INSERT INTO fido_credentials VALUES (
            'cred-1',
            'google.com',
            'alice@gmail.com',
            'Alice G.',
            'base64-credential-id-123',
            1710000000,
            1715000000
        )
        """
    )
    cur.execute(
        """
        INSERT INTO fido_credentials VALUES (
            'cred-2',
            'github.com',
            'alice_dev',
            'Alice',
            'base64-credential-id-456',
            1712000000,
            1716000000
        )
        """
    )
    conn.commit()
    conn.close()

    records = parse_passkey_database(db)
    assert len(records) == 2

    r1 = next(r for r in records if r.rp_id == "google.com")
    assert r1.user_name == "alice@gmail.com"
    assert r1.user_display_name == "Alice G."
    assert r1.credential_id == "base64-credential-id-123"
    assert r1.created_epoch == 1710000000
    assert r1.last_used_epoch == 1715000000

    r2 = next(r for r in records if r.rp_id == "github.com")
    assert r2.user_name == "alice_dev"
    assert r2.credential_id == "base64-credential-id-456"


def test_find_passkey_artifacts_targeted_paths() -> None:
    dev = MagicMock(spec=DeviceManager)
    dev.has_root.return_value = True

    def fake_shell(serial: str, cmd: str, timeout_s: float = 5.0) -> str:
        if "test -f" in cmd:
            if "fido2.db" in cmd:
                return "exists\n"
        return ""

    dev.shell.side_effect = fake_shell
    found = find_passkey_artifacts(dev, "serial-123")
    assert len(found) >= 1
    assert any("fido2.db" in p for p in found)


def test_pull_and_workflow_passkeys(monkeypatch, tmp_path: pathlib.Path) -> None:
    dev = MagicMock(spec=DeviceManager)
    dev.has_root.return_value = True
    dev.info.return_value.props = {}

    target_db = tmp_path / "fido2.db"
    conn = sqlite3.connect(str(target_db))
    cur = conn.cursor()
    cur.execute("CREATE TABLE fido_credentials (rp_id TEXT, credential_id TEXT, user_name TEXT)")
    cur.execute(
        "INSERT INTO fido_credentials VALUES ('apple.com', 'cred-apple-789', 'user@icloud.com')"
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(
        "lockknife.modules.credentials.fido2.find_passkey_artifacts",
        lambda d, s, limit=200: ["/data/user/0/com.google.android.gms/databases/fido2.db"],
    )

    def fake_shell(serial: str, cmd: str, timeout_s: float = 30.0) -> str:
        return ""

    def fake_pull(serial: str, remote: str, local: pathlib.Path, timeout_s: float = 120.0):
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(target_db.read_bytes())

    dev.shell.side_effect = fake_shell
    dev.pull.side_effect = fake_pull

    out_dir = tmp_path / "passkeys_out"
    artifacts = pull_passkey_artifacts(dev, "serial-123", output_dir=out_dir)
    assert len(artifacts) == 1
    assert artifacts[0].local_path is not None
    assert pathlib.Path(artifacts[0].local_path).exists()

    parsed = parse_passkey_database(pathlib.Path(artifacts[0].local_path))
    assert len(parsed) == 1
    assert parsed[0].rp_id == "apple.com"
    assert parsed[0].credential_id == "cred-apple-789"


def test_cli_crack_passkeys_command(monkeypatch, tmp_path: pathlib.Path) -> None:
    fake_dev = MagicMock(spec=DeviceManager)
    fake_dev.has_root.return_value = True
    fake_dev.info.return_value.props = {}
    fake_dev.list_handles.return_value = [
        DeviceHandle(serial="test-serial", adb_state="device", state=DeviceState.authorized)
    ]

    class FakeApp:
        devices = fake_dev

    out_dir = tmp_path / "cli_passkeys"
    out_dir.mkdir(parents=True, exist_ok=True)

    test_db = out_dir / "fido2.db"
    conn = sqlite3.connect(str(test_db))
    cur = conn.cursor()
    cur.execute("CREATE TABLE fido_credentials (rp_id TEXT, credential_id TEXT, user_name TEXT)")
    cur.execute("INSERT INTO fido_credentials VALUES ('github.com', 'cred-gh-123', 'octocat')")
    conn.commit()
    conn.close()

    monkeypatch.setattr(
        "lockknife_headless_cli.crack.pull_passkey_artifacts",
        lambda d, s, output_dir, limit=200: [
            PasskeyArtifact(
                remote_path="/data/fido2.db", local_path=str(test_db), size=test_db.stat().st_size
            )
        ],
    )

    runner = CliRunner()
    res = runner.invoke(
        crack,
        ["passkeys", "--serial", "test-serial", "--output-dir", str(out_dir)],
        obj=FakeApp(),
    )
    assert res.exit_code == 0
    assert (out_dir / "passkeys_manifest.json").exists()
    assert (out_dir / "passkeys.json").exists()
