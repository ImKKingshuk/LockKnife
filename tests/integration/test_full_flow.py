import pathlib
import sqlite3
from unittest import mock


def test_full_cli_flow_with_mocked_device(tmp_path: pathlib.Path) -> None:
    """Integration test for full CLI flow: device mock → extract → forensics."""
    from lockknife.modules.credentials.gesture import recover_gesture
    from lockknife.modules.extraction.contacts import extract_contacts
    from lockknife.modules.extraction.sms import extract_sms

    # Create minimal mocked device databases
    sms_db = tmp_path / "mmssms.db"
    con = sqlite3.connect(str(sms_db))
    try:
        con.execute("CREATE TABLE sms (address TEXT, body TEXT, date INTEGER, type INTEGER)")
        con.execute("INSERT INTO sms VALUES ('+15551234567', 'Test message', 1700000000, 1)")
        con.commit()
    finally:
        con.close()

    contacts_db = tmp_path / "contacts2.db"
    con = sqlite3.connect(str(contacts_db))
    try:
        con.execute("CREATE TABLE contacts (_id INTEGER, display_name TEXT)")
        con.execute("INSERT INTO contacts VALUES (1, 'Test Contact')")
        con.commit()
    finally:
        con.close()

    # Get gesture key from lockknife_core
    lockknife_core = __import__("pytest").importorskip("lockknife.lockknife_core")
    gesture_key = bytes.fromhex(lockknife_core.sha1_hex(bytes([0, 1, 2, 3])))

    # Mock device with pull method
    dev = mock.Mock()
    dev.has_root.return_value = True
    dev.serial.return_value = "TEST_DEVICE"

    def pull(serial: str, remote: str, local: pathlib.Path, timeout_s: float = 0.0) -> None:
        local.parent.mkdir(parents=True, exist_ok=True)
        if remote.endswith("mmssms.db"):
            local.write_bytes(sms_db.read_bytes())
        elif remote.endswith("contacts2.db"):
            local.write_bytes(contacts_db.read_bytes())
        elif remote.endswith("gesture.key"):
            local.write_bytes(gesture_key)
        else:
            # Create empty file for other paths
            local.write_bytes(b"")

    dev.pull.side_effect = pull

    # Test extraction flow
    sms_messages = extract_sms(dev, "TEST_DEVICE", limit=10)
    assert len(sms_messages) == 1
    assert sms_messages[0].body == "Test message"
    assert sms_messages[0].address == "+15551234567"

    contacts = extract_contacts(dev, "TEST_DEVICE", limit=10)
    assert len(contacts) == 1
    assert contacts[0].display_name == "Test Contact"

    # Test gesture recovery
    gesture = recover_gesture(dev, "TEST_DEVICE")
    assert gesture == "1-2-3-4"
