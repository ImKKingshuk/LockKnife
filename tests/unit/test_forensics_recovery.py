import pathlib

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
