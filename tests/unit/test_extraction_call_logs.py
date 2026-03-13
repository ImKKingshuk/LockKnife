import pathlib
import sqlite3

from lockknife.modules.extraction.call_logs import _parse_calls_db


def test_parse_calls_db(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "calllog.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE calls (number TEXT, date INTEGER, duration INTEGER, type INTEGER, name TEXT)")
        con.execute("INSERT INTO calls VALUES ('+1', 10, 3, 1, 'Alice')")
        con.execute("INSERT INTO calls VALUES ('+2', 20, 4, 2, 'Bob')")
        con.commit()
    finally:
        con.close()
    calls = _parse_calls_db(db, limit=10)
    assert calls[0].number == "+2"
    assert calls[0].cached_name == "Bob"

