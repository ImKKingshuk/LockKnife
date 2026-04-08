import pathlib
import sqlite3

from lockknife.modules.extraction.messaging import _parse_telegram_cache


def test_parse_telegram_cache_messages_v2(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "cache4.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute(
            "CREATE TABLE messages_v2 (uid INTEGER, mid INTEGER, date INTEGER, out INTEGER, data BLOB)"
        )
        con.execute("INSERT INTO messages_v2 VALUES (1, 2, 3, 1, X'0102')")
        con.commit()
    finally:
        con.close()
    rows = _parse_telegram_cache(db, 10)
    assert rows[0].uid == 1
    assert rows[0].data_b64 is not None
