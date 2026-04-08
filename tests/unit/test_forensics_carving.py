import pathlib

from lockknife.modules.forensics.carving import carve_deleted_files


def test_carve_deleted_files_from_raw_image(tmp_path: pathlib.Path) -> None:
    image = tmp_path / "image.bin"
    image.write_bytes(b"\x00\x00" + b"\xff\xd8\xffhello" + b"\xff\xd9" + b"\x00")

    output_dir = tmp_path / "carved"
    result = carve_deleted_files(image, output_dir, source="image", max_matches=5)

    assert result["carved_count"] == 1
    assert pathlib.Path(result["carved"][0]["path"]).exists()
    assert result["carved"][0]["source_kind"] == "raw-image"


def test_carve_deleted_files_uses_sqlite_sources(tmp_path: pathlib.Path) -> None:
    page_size = 4096
    db = tmp_path / "x.db"
    header = bytearray(b"SQLite format 3\x00" + b"\x00" * (100 - 16))
    header[16:18] = page_size.to_bytes(2, "big")
    body = b"\x00" * 100 + b"%PDF-1.7 demo%%EOF"
    db.write_bytes(bytes(header) + body)

    result = carve_deleted_files(db, tmp_path / "carved-sqlite", source="sqlite", max_matches=5)

    assert result["sources"][0]["source_kind"] == "main-db"
    assert result["carved_count"] >= 1
