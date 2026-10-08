from __future__ import annotations

import pathlib
from typing import Any, TypedDict

from lockknife.modules.forensics.recovery import _recovery_sources, _sqlite_page_size


class _CarveSignature(TypedDict):
    kind: str
    header: bytes
    footer: bytes
    extension: str
    max_size: int


_SIGNATURES: list[_CarveSignature] = [
    {
        "kind": "jpg",
        "header": b"\xff\xd8\xff",
        "footer": b"\xff\xd9",
        "extension": ".jpg",
        "max_size": 25 * 1024 * 1024,
    },
    {
        "kind": "png",
        "header": b"\x89PNG\r\n\x1a\n",
        "footer": b"IEND\xaeB`\x82",
        "extension": ".png",
        "max_size": 25 * 1024 * 1024,
    },
    {
        "kind": "pdf",
        "header": b"%PDF-",
        "footer": b"%%EOF",
        "extension": ".pdf",
        "max_size": 50 * 1024 * 1024,
    },
    {
        "kind": "zip",
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "extension": ".zip",
        "max_size": 50 * 1024 * 1024,
    },
]


def carve_deleted_files(
    input_path: pathlib.Path,
    output_dir: pathlib.Path,
    *,
    source: str = "auto",
    max_matches: int = 50,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not input_path.exists():
        return {
            "input": str(input_path),
            "source": source,
            "output_dir": str(output_dir),
            "carved_count": 0,
            "sources": [],
            "carved": [],
            "error": f"Input path does not exist: {input_path}",
        }

    scan_sources = _scan_sources(input_path, source=source)
    carved: list[dict[str, Any]] = []
    counter = 0
    seen_offsets: set[int] = set()
    for source_entry in scan_sources:
        batch, counter = _carve_from_blob(
            source_entry,
            output_dir=output_dir,
            max_matches=max_matches - len(carved),
            counter=counter,
            seen_offsets=seen_offsets,
        )
        carved.extend(batch)
        if len(carved) >= max_matches:
            break
    return {
        "input": str(input_path),
        "source": source,
        "output_dir": str(output_dir),
        "carved_count": len(carved),
        "sources": [
            {key: value for key, value in item.items() if key != "blob"} for item in scan_sources
        ],
        "carved": carved,
    }


def _scan_sources(input_path: pathlib.Path, *, source: str) -> list[dict[str, Any]]:
    if not input_path.exists():
        return []
    file_size = input_path.stat().st_size
    if file_size == 0:
        return []

    # Read minimal header to determine file type without reading whole file
    with input_path.open("rb") as f:
        header_16 = f.read(16)

    is_sqlite = header_16.startswith(b"SQLite format 3\x00")
    if source == "sqlite" or (source == "auto" and is_sqlite):
        raw = input_path.read_bytes()
        page_size = _sqlite_page_size(raw)
        return _recovery_sources(input_path, raw, page_size=page_size)

    # For raw images: if file size <= 32MB, load directly
    max_chunk = 32 * 1024 * 1024
    if file_size <= max_chunk:
        raw = input_path.read_bytes()
        return [{"source_kind": "raw-image", "origin": str(input_path), "offset": 0, "blob": raw}]

    # For large raw images: stream in overlapping chunks to prevent memory exhaustion (OOM)
    chunks: list[dict[str, Any]] = []
    overlap = 50 * 1024 * 1024  # Max signature size across signatures
    step = max(max_chunk, overlap // 2)
    with input_path.open("rb") as f:
        offset = 0
        while offset < file_size:
            f.seek(offset)
            data = f.read(step + overlap)
            if not data:
                break
            chunks.append(
                {
                    "source_kind": "raw-image",
                    "origin": str(input_path),
                    "offset": offset,
                    "blob": data,
                }
            )
            offset += step
            if offset >= file_size:
                break
    return chunks


def _carve_from_blob(
    source_entry: dict[str, Any],
    *,
    output_dir: pathlib.Path,
    max_matches: int,
    counter: int,
    seen_offsets: set[int] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    blob = bytes(source_entry.get("blob") or b"")
    if max_matches <= 0:
        return [], counter
    if seen_offsets is None:
        seen_offsets = set()
    out: list[dict[str, Any]] = []
    for signature in _SIGNATURES:
        start = 0
        while len(out) < max_matches:
            index = blob.find(signature["header"], start)
            if index < 0:
                break
            end_index = blob.find(signature["footer"], index + len(signature["header"]))
            if end_index < 0:
                start = index + len(signature["header"])
                continue
            end = min(end_index + len(signature["footer"]), index + int(signature["max_size"]))
            abs_offset = int(source_entry.get("offset") or 0) + index
            if abs_offset in seen_offsets:
                start = end
                continue
            seen_offsets.add(abs_offset)
            carved_bytes = blob[index:end]
            file_name = f"carved_{counter:03d}_{signature['kind']}{signature['extension']}"
            path = output_dir / file_name
            path.write_bytes(carved_bytes)
            out.append(
                {
                    "kind": signature["kind"],
                    "path": str(path),
                    "size_bytes": len(carved_bytes),
                    "source_kind": source_entry.get("source_kind"),
                    "origin": source_entry.get("origin"),
                    "offset": abs_offset,
                    "page_number": source_entry.get("page_number"),
                }
            )
            start = end
            counter += 1
    return out, counter
