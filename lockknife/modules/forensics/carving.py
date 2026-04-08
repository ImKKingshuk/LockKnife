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
    scan_sources = _scan_sources(input_path, source=source)
    carved: list[dict[str, Any]] = []
    counter = 0
    for source_entry in scan_sources:
        batch, counter = _carve_from_blob(
            source_entry,
            output_dir=output_dir,
            max_matches=max_matches - len(carved),
            counter=counter,
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
    raw = input_path.read_bytes()
    if source == "image":
        return [{"source_kind": "raw-image", "origin": str(input_path), "offset": 0, "blob": raw}]
    if source == "sqlite" or (source == "auto" and raw.startswith(b"SQLite format 3\x00")):
        page_size = _sqlite_page_size(raw)
        return _recovery_sources(input_path, raw, page_size=page_size)
    return [{"source_kind": "raw-image", "origin": str(input_path), "offset": 0, "blob": raw}]


def _carve_from_blob(
    source_entry: dict[str, Any], *, output_dir: pathlib.Path, max_matches: int, counter: int
) -> tuple[list[dict[str, Any]], int]:
    blob = bytes(source_entry.get("blob") or b"")
    if max_matches <= 0:
        return [], counter
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
                    "offset": int(source_entry.get("offset") or 0) + index,
                    "page_number": source_entry.get("page_number"),
                }
            )
            start = end
            counter += 1
    return out, counter
