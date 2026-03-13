import pathlib
import sqlite3

from lockknife.modules.forensics.sqlite_analyzer import analyze_sqlite


def test_analyze_sqlite_tables(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "x.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE t (id INTEGER)")
        con.execute("INSERT INTO t VALUES (1)")
        con.commit()
    finally:
        con.close()
    analysis = analyze_sqlite(db)
    table = next(t for t in analysis.tables if t.name == "t")
    assert table.row_count == 1
    assert table.columns[0].name == "id"
    assert analysis.summary["table_count"] == 1
    assert analysis.wal["exists"] is False

