import pathlib
import sqlite3

from lockknife.modules.extraction.contacts import _parse_contacts2_db


def test_parse_contacts2_db_with_phone_join(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "contacts2.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE contacts (_id INTEGER, display_name TEXT)")
        con.execute("CREATE TABLE raw_contacts (_id INTEGER, contact_id INTEGER)")
        con.execute("CREATE TABLE data (_id INTEGER, raw_contact_id INTEGER, mimetype TEXT, data1 TEXT)")
        con.execute("INSERT INTO contacts VALUES (1, 'Alice')")
        con.execute("INSERT INTO raw_contacts VALUES (10, 1)")
        con.execute(
            "INSERT INTO data VALUES (100, 10, 'vnd.android.cursor.item/phone_v2', '+111')"
        )
        con.commit()
    finally:
        con.close()

    contacts = _parse_contacts2_db(db, limit=10)
    assert contacts[0].display_name == "Alice"
    assert contacts[0].number == "+111"

