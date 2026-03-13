import pathlib
import sqlite3

from lockknife.modules.extraction.sms import _parse_mmssms_db


def test_parse_mmssms_db(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "mmssms.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE sms (address TEXT, body TEXT, date INTEGER, type INTEGER)")
        con.execute("INSERT INTO sms(address, body, date, type) VALUES (?, ?, ?, ?)", ("+123", "hi", 10, 1))
        con.execute("INSERT INTO sms(address, body, date, type) VALUES (?, ?, ?, ?)", ("+456", "yo", 20, 2))
        con.commit()
    finally:
        con.close()
    msgs = _parse_mmssms_db(db, limit=10)
    assert msgs[0].address == "+456"
    assert msgs[0].body == "yo"

