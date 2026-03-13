import pathlib
import sqlite3
from unittest import mock


def test_end_to_end_sms_contacts_gesture(tmp_path: pathlib.Path) -> None:
    from lockknife.modules.credentials.gesture import recover_gesture
    from lockknife.modules.extraction.contacts import extract_contacts
    from lockknife.modules.extraction.sms import extract_sms

    sms_db = tmp_path / "mmssms.db"
    con = sqlite3.connect(str(sms_db))
    try:
        con.execute("CREATE TABLE sms (address TEXT, body TEXT, date INTEGER, type INTEGER)")
        con.execute("INSERT INTO sms VALUES ('+1', 'hi', 1, 1)")
        con.commit()
    finally:
        con.close()

    contacts_db = tmp_path / "contacts2.db"
    con = sqlite3.connect(str(contacts_db))
    try:
        con.execute("CREATE TABLE contacts (_id INTEGER, display_name TEXT)")
        con.execute("INSERT INTO contacts VALUES (1, 'n')")
        con.commit()
    finally:
        con.close()

    lockknife_core = __import__("pytest").importorskip("lockknife.lockknife_core")
    gesture_key = bytes.fromhex(lockknife_core.sha1_hex(bytes([0, 1, 2, 3])))

    dev = mock.Mock()
    dev.has_root.return_value = True

    def pull(serial: str, remote: str, local: pathlib.Path, timeout_s: float = 0.0) -> None:
        local.parent.mkdir(parents=True, exist_ok=True)
        if remote.endswith("mmssms.db"):
            local.write_bytes(sms_db.read_bytes())
        elif remote.endswith("contacts2.db"):
            local.write_bytes(contacts_db.read_bytes())
        else:
            local.write_bytes(gesture_key)

    dev.pull.side_effect = pull

    assert extract_sms(dev, "SER", limit=10)[0].body == "hi"
    assert extract_contacts(dev, "SER", limit=10)[0].display_name == "n"
    assert recover_gesture(dev, "SER") == "1-2-3-4"
