import pathlib
import sqlite3
from contextlib import closing

import pytest

from lockknife.modules.forensics import recovery
from lockknife.modules.forensics.recovery import recover_deleted_records


def test_recover_deleted_records_scans_db_bytes(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "x.db"
    header = bytearray(b"SQLite format 3\x00" + b"\x00" * (100 - 16))
    header[16:18] = (4096).to_bytes(2, "big")
    body = b"\x00" * 200 + b"https://example.com/x" + b"\x00" * 50
    p.write_bytes(bytes(header) + body)
    out = recover_deleted_records(p, max_fragments=20)
    texts = [f["text"] for f in out["fragments"]]
    assert "https://example.com/x" in texts
    assert out["summary"]["fragment_count"] >= 1
    assert out["summary"]["source_counts"]["main-db"] >= 1


def test_recover_deleted_records_walks_freelist_pages(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "freelist.db"
    page_size = 4096
    header = bytearray(b"SQLite format 3\x00" + b"\x00" * (100 - 16))
    header[16:18] = page_size.to_bytes(2, "big")
    header[32:36] = (2).to_bytes(4, "big")
    header[36:40] = (2).to_bytes(4, "big")
    page2 = bytearray(page_size)
    page2[0:4] = (0).to_bytes(4, "big")
    page2[4:8] = (1).to_bytes(4, "big")
    page2[8:12] = (3).to_bytes(4, "big")
    page3 = bytearray(page_size)
    page3[32 : 32 + len(b"alice@example.com")] = b"alice@example.com"
    p.write_bytes(bytes(header) + b"\x00" * (page_size - len(header)) + bytes(page2) + bytes(page3))

    out = recover_deleted_records(p, max_fragments=20)

    assert len(out["page_analysis"]["freelist_pages"]) >= 2
    assert any(fragment["source_kind"] == "freelist-page" for fragment in out["fragments"])


@pytest.mark.parametrize("connection_default", [0, 1], ids=["default-off", "default-on"])
@pytest.mark.parametrize("secure_delete", [False, True], ids=["retained", "erased"])
@pytest.mark.parametrize(
    "python_fallback", [False, True], ids=["default-backend", "python-fallback"]
)
def test_recover_deleted_records_recovers_structured_deleted_rows(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    connection_default: int,
    secure_delete: bool,
    python_fallback: bool,
) -> None:
    if python_fallback:
        monkeypatch.setattr(recovery, "_native_sqlite_carve_records", None)

    db_path = tmp_path / "example-evidence.db"
    deleted_email = "person-b@example.invalid"
    with closing(sqlite3.connect(db_path)) as con:
        # Model both platform defaults, then explicitly select this fixture's deletion behavior.
        con.execute(f"PRAGMA secure_delete = {connection_default}")
        con.execute(f"PRAGMA secure_delete = {int(secure_delete)}")
        assert con.execute("PRAGMA secure_delete").fetchone()[0] == int(secure_delete)
        con.execute("PRAGMA auto_vacuum = NONE")
        con.execute("PRAGMA journal_mode = DELETE")
        con.execute(
            "CREATE TABLE evidence (id INTEGER PRIMARY KEY, suspect TEXT, email TEXT, notes TEXT)"
        )
        con.executemany(
            "INSERT INTO evidence VALUES (?, ?, ?, ?)",
            [
                (1, "Example Person A", "person-a@example.invalid", "Example note A"),
                (2, "Example Person B", deleted_email, "Example note B"),
                (3, "Example Person C", "person-c@example.invalid", "Example note C"),
            ],
        )
        con.commit()
        con.execute("DELETE FROM evidence WHERE id = ?", (2,))
        con.commit()
        assert con.execute("SELECT email FROM evidence WHERE id = ?", (2,)).fetchone() is None

    assert (deleted_email.encode() in db_path.read_bytes()) is not secure_delete

    res = recover_deleted_records(db_path, max_fragments=100)
    assert res["summary"]["record_count"] >= 1 or res["summary"]["fragment_count"] >= 1

    all_record_values = [
        str(col) for rec in res.get("records", []) for col in rec.get("columns", [])
    ]
    all_fragment_texts = [f["text"] for f in res.get("fragments", [])]
    combined_matches = " ".join(all_record_values + all_fragment_texts)

    if secure_delete:
        assert deleted_email not in combined_matches
        assert "Example Person B" not in combined_matches
    else:
        assert deleted_email in combined_matches
