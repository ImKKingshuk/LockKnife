import pathlib
import sqlite3

from lockknife.modules.credentials.pin import _extract_salt_from_locksettings_db, _extract_sha1_from_password_key


def test_extract_salt_from_locksettings_db(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "locksettings.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE locksettings (name TEXT, value TEXT)")
        con.execute(
            "INSERT INTO locksettings(name, value) VALUES (?, ?)",
            ("lockscreen.password_salt", "123456789"),
        )
        con.commit()
    finally:
        con.close()
    assert _extract_salt_from_locksettings_db(db) == 123456789


def test_extract_sha1_from_password_key(tmp_path: pathlib.Path) -> None:
    key = tmp_path / "password.key"
    key.write_bytes(bytes.fromhex("00" * 20) + b"rest")
    assert _extract_sha1_from_password_key(key) == "00" * 20

