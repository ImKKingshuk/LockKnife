import pathlib
import sqlite3
import types

import pytest

from lockknife.core.exceptions import DeviceError
from lockknife.modules.extraction.messaging import (
    _parse_signal_db,
    _parse_whatsapp_msgstore,
    _try_root_pull_file,
    extract_signal_artifacts,
    extract_signal_messages,
    extract_telegram_artifacts,
    extract_telegram_messages,
    extract_whatsapp_artifacts,
    extract_whatsapp_messages,
)


class _Devices:
    def __init__(self, *, rooted: bool = True, shell_map: dict[str, str] | None = None) -> None:
        self.rooted = rooted
        self.shell_map = shell_map or {}
        self.pull_payloads: dict[str, bytes] = {}

    def has_root(self, _serial: str) -> bool:
        return self.rooted

    def pull(
        self, _serial: str, remote: str, local: pathlib.Path, timeout_s: float = 120.0
    ) -> None:
        payload = self.pull_payloads.get(remote)
        if payload is None:
            raise DeviceError("missing remote")
        local.write_bytes(payload)

    def shell(self, _serial: str, command: str, timeout_s: float = 20.0) -> str:
        if "cp '" in command and "/sdcard/lockknife-tmp-" in command:
            marker = command.split("cp '", 1)[1].split("' ", 1)[0]
            tmp_remote = (
                command.split(" > '", 1)[-1].split("'", 1)[0] if " > '" in command else None
            )
            if tmp_remote and marker in self.pull_payloads:
                self.pull_payloads[tmp_remote] = self.pull_payloads[marker]
            elif marker in self.pull_payloads:
                tmp_path = f"/sdcard/lockknife-tmp-{pathlib.Path(marker).name}"
                self.pull_payloads[tmp_path] = self.pull_payloads[marker]
            return "ok"
        for key, value in self.shell_map.items():
            if key in command:
                if isinstance(value, Exception):
                    raise value
                return value
        return ""


def test_parse_whatsapp_and_signal_databases(tmp_path: pathlib.Path) -> None:
    wa = tmp_path / "msgstore.db"
    con = sqlite3.connect(str(wa))
    try:
        con.execute("CREATE TABLE messages (key_remote_jid TEXT, data TEXT, timestamp INTEGER)")
        con.execute("INSERT INTO messages VALUES ('jid', 'hello', 123)")
        con.commit()
    finally:
        con.close()
    rows = _parse_whatsapp_msgstore(wa, 10)
    assert rows[0].jid == "jid"
    assert rows[0].timestamp_ms == 123

    signal = tmp_path / "signal.db"
    con = sqlite3.connect(str(signal))
    try:
        con.execute("CREATE TABLE sms (date INTEGER, body TEXT)")
        con.execute("INSERT INTO sms VALUES (456, 'body')")
        con.commit()
    finally:
        con.close()
    signal_rows = _parse_signal_db(signal, 10)
    assert signal_rows[0].thread_id is None
    assert signal_rows[0].body == "body"


def test_messaging_root_pull_and_extractors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    wa = tmp_path / "msgstore.db"
    con = sqlite3.connect(str(wa))
    try:
        con.execute("CREATE TABLE messages (key_remote_jid TEXT, data TEXT, timestamp INTEGER)")
        con.execute("INSERT INTO messages VALUES ('wa', 'hello', 1)")
        con.commit()
    finally:
        con.close()

    tg = tmp_path / "cache4.db"
    con = sqlite3.connect(str(tg))
    try:
        con.execute(
            "CREATE TABLE messages (uid INTEGER, mid INTEGER, date INTEGER, out INTEGER, data BLOB)"
        )
        con.execute("INSERT INTO messages VALUES (1, 2, 3, 0, X'0102')")
        con.commit()
    finally:
        con.close()

    sig = tmp_path / "signal.db"
    con = sqlite3.connect(str(sig))
    try:
        con.execute("CREATE TABLE sms (thread_id INTEGER, date INTEGER, body TEXT)")
        con.execute("INSERT INTO sms VALUES (9, 10, 'sig')")
        con.commit()
    finally:
        con.close()

    devices = _Devices(
        shell_map={
            "WhatsApp/Databases": "msgstore.db.crypt14\nmsgstore.db\n",
            "/files/key": "key\n",
            "org.telegram.messenger/files": "cache4.db\n",
            "org.telegram.messenger/databases": RuntimeError("denied"),
            "org.thoughtcrime.securesms/databases": "signal.db\n",
            "org.thoughtcrime.securesms/shared_prefs": "prefs.xml\n",
        }
    )
    devices.pull_payloads = {
        "/data/data/com.whatsapp/databases/msgstore.db": wa.read_bytes(),
        "/data/data/org.telegram.messenger/files/cache4.db": tg.read_bytes(),
        "/data/data/org.thoughtcrime.securesms/databases/signal.db": sig.read_bytes(),
    }

    pulled = tmp_path / "root.bin"
    assert (
        _try_root_pull_file(
            devices,
            "SERIAL",
            "/data/data/com.whatsapp/databases/msgstore.db",
            pulled,
            timeout_s=1.0,
        )
        is True
    )
    assert pulled.exists()

    assert extract_whatsapp_messages(devices, "SERIAL")[0].jid == "wa"
    assert extract_telegram_messages(devices, "SERIAL")[0].uid == 1
    assert extract_signal_messages(devices, "SERIAL")[0].thread_id == 9

    wa_artifacts = extract_whatsapp_artifacts(devices, "SERIAL")
    assert wa_artifacts.encrypted is True
    assert any(path.endswith("key") for path in wa_artifacts.db_paths)

    tg_artifacts = extract_telegram_artifacts(devices, "SERIAL")
    assert tg_artifacts.app == "telegram"
    assert "/data/data/org.telegram.messenger/files/cache4.db" in tg_artifacts.db_paths
    assert len(tg_artifacts.db_paths) >= 1

    sig_artifacts = extract_signal_artifacts(devices, "SERIAL")
    assert sig_artifacts.encrypted is True
    assert any(path.endswith("prefs.xml") for path in sig_artifacts.db_paths)


def test_signal_messages_root_and_encrypted_error(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(DeviceError):
        extract_signal_messages(types.SimpleNamespace(has_root=lambda _serial: False), "SERIAL")

    import lockknife.modules.extraction.messaging as messaging_mod

    monkeypatch.setattr(messaging_mod, "_try_root_pull_file", lambda *_a, **_k: True)
    monkeypatch.setattr(
        messaging_mod,
        "_parse_signal_db",
        lambda *_a, **_k: (_ for _ in ()).throw(sqlite3.DatabaseError("cipher")),
    )
    with pytest.raises(DeviceError, match="encrypted or unreadable"):
        extract_signal_messages(types.SimpleNamespace(has_root=lambda _serial: True), "SERIAL")
