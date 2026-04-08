from __future__ import annotations

import pathlib
import re
from collections import Counter
from typing import Any

_RE_URL = re.compile(r"https?://[^\s\"'<>]+")
_RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_RE_PHONE = re.compile(r"\+?\d[\d -]{7,}\d")


def recover_deleted_records(db_path: pathlib.Path, *, max_fragments: int = 500) -> dict[str, Any]:
    raw = db_path.read_bytes()
    page_size = _sqlite_page_size(raw)
    if page_size <= 0:
        return {"path": str(db_path), "error": "Not a SQLite database", "fragments": []}
    sources = _recovery_sources(db_path, raw, page_size=page_size)
    fragments: list[dict[str, Any]] = []
    for source in sources:
        fragments.extend(_fragments_from_blob(source, limit=max_fragments))
        if len(fragments) >= max_fragments:
            break
    unique = _dedupe_fragments(fragments)[:max_fragments]
    source_counts = Counter(str(fragment.get("source_kind") or "unknown") for fragment in unique)
    return {
        "path": str(db_path),
        "summary": {
            "fragment_count": len(unique),
            "page_size": page_size,
            "high_confidence_count": sum(
                1 for fragment in unique if fragment.get("confidence") == "high"
            ),
            "source_counts": dict(sorted(source_counts.items())),
        },
        "page_analysis": {
            "page_size": page_size,
            "total_pages": len(raw) // page_size if page_size else 0,
            "freelist_pages": [
                entry["page_number"]
                for entry in sources
                if entry.get("source_kind") == "freelist-page"
            ],
            "overflow_pages": [
                entry["page_number"]
                for entry in sources
                if entry.get("source_kind") == "overflow-page"
            ],
            "rollback_journal_present": any(
                entry.get("source_kind") == "rollback-journal" for entry in sources
            ),
            "wal_present": any(entry.get("source_kind") == "wal-frame" for entry in sources),
        },
        "sources": [
            {key: value for key, value in source.items() if key != "blob"} for source in sources
        ],
        "fragments": unique,
    }


def _recovery_sources(db_path: pathlib.Path, raw: bytes, *, page_size: int) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = [
        {"source_kind": "main-db", "origin": str(db_path), "offset": 0, "blob": raw},
    ]
    for page_number in _freelist_pages(raw, page_size=page_size):
        start = (page_number - 1) * page_size
        end = start + page_size
        if end <= len(raw):
            sources.append(
                {
                    "source_kind": "freelist-page",
                    "origin": str(db_path),
                    "page_number": page_number,
                    "offset": start,
                    "blob": raw[start:end],
                }
            )
    for page_number in _overflow_candidates(raw, page_size=page_size):
        start = (page_number - 1) * page_size
        end = start + page_size
        if end <= len(raw):
            sources.append(
                {
                    "source_kind": "overflow-page",
                    "origin": str(db_path),
                    "page_number": page_number,
                    "offset": start,
                    "blob": raw[start:end],
                }
            )
    journal_path = db_path.with_name(db_path.name + "-journal")
    if journal_path.exists():
        sources.append(
            {
                "source_kind": "rollback-journal",
                "origin": str(journal_path),
                "offset": 0,
                "blob": journal_path.read_bytes(),
            }
        )
    wal_path = db_path.with_name(db_path.name + "-wal")
    if wal_path.exists():
        sources.extend(
            _wal_frames(wal_path.read_bytes(), page_size=page_size, origin=str(wal_path))
        )
    return sources


def _fragments_from_blob(source: dict[str, Any], *, limit: int) -> list[dict[str, Any]]:
    blob = bytes(source.get("blob") or b"")
    base_offset = int(source.get("offset") or 0)
    out: list[dict[str, Any]] = []
    for match in re.finditer(rb"[\x20-\x7e]{6,}", blob):
        text = match.group(0).decode("utf-8", errors="ignore")
        fragments = _extract_interesting_fragments(text)
        if not fragments:
            continue
        for fragment_text, relative_offset in fragments:
            out.append(
                {
                    "text": fragment_text,
                    "offset": base_offset + match.start() + relative_offset,
                    "page_number": source.get("page_number"),
                    "source_kind": source.get("source_kind"),
                    "origin": source.get("origin"),
                    "confidence": _confidence(
                        fragment_text, source_kind=str(source.get("source_kind") or "main-db")
                    ),
                }
            )
            if len(out) >= limit:
                return out
    return out


def _dedupe_fragments(fragments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, int | None]] = set()
    out: list[dict[str, Any]] = []
    for fragment in fragments:
        key = (
            str(fragment.get("text") or ""),
            str(fragment.get("source_kind") or ""),
            fragment.get("page_number"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(fragment)
    return out


def _interesting(text: str) -> bool:
    lowered = text.lower()
    return any(
        token in lowered for token in ("http", "@", "session", "chat", "token", "login", "message")
    )


def _extract_interesting_fragments(text: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for regex in (_RE_URL, _RE_EMAIL, _RE_PHONE):
        for match in regex.finditer(text):
            out.append((match.group(0), match.start()))
    if out:
        return out
    return [(text, 0)] if _interesting(text) else []


def _confidence(text: str, *, source_kind: str) -> str:
    lowered = text.lower()
    if any(token in lowered for token in ("http://", "https://", "@", "token", "password")):
        return "high" if source_kind != "main-db" else "medium"
    if any(token in lowered for token in ("chat", "message", "login", "session")):
        return "medium"
    return "low"


def _sqlite_page_size(db: bytes) -> int:
    if len(db) < 100 or not db.startswith(b"SQLite format 3\x00"):
        return 0
    ps = int.from_bytes(db[16:18], "big")
    return 65536 if ps == 1 else ps


def _freelist_pages(raw: bytes, *, page_size: int) -> list[int]:
    if page_size <= 0 or len(raw) < 40:
        return []
    first_trunk = int.from_bytes(raw[32:36], "big")
    total_pages = len(raw) // page_size
    seen: set[int] = set()
    out: list[int] = []
    page = first_trunk
    while 0 < page <= total_pages and page not in seen:
        seen.add(page)
        out.append(page)
        start = (page - 1) * page_size
        trunk = raw[start : start + page_size]
        next_trunk = int.from_bytes(trunk[0:4], "big") if len(trunk) >= 4 else 0
        leaf_count = int.from_bytes(trunk[4:8], "big") if len(trunk) >= 8 else 0
        for index in range(min(leaf_count, max((len(trunk) - 8) // 4, 0))):
            pointer = int.from_bytes(trunk[8 + (index * 4) : 12 + (index * 4)], "big")
            if 0 < pointer <= total_pages:
                out.append(pointer)
        page = next_trunk
    return sorted(set(out))


def _overflow_candidates(raw: bytes, *, page_size: int) -> list[int]:
    total_pages = len(raw) // page_size if page_size else 0
    known = set(_freelist_pages(raw, page_size=page_size))
    out: list[int] = []
    for page_number in range(2, total_pages + 1):
        if page_number in known:
            continue
        start = (page_number - 1) * page_size
        page = raw[start : start + page_size]
        if len(page) < 8:
            continue
        page_type = page[0]
        next_page = int.from_bytes(page[:4], "big")
        ascii_hits = len(re.findall(rb"[\x20-\x7e]{6,}", page))
        if (
            page_type not in {0x02, 0x05, 0x0A, 0x0D}
            and 0 < next_page <= total_pages
            and ascii_hits
        ):
            out.append(page_number)
    return out


def _wal_frames(wal: bytes, *, page_size: int, origin: str) -> list[dict[str, Any]]:
    if len(wal) < 32:
        return []
    frame_page_size = page_size or int.from_bytes(wal[8:12], "big")
    if frame_page_size <= 0:
        return []
    out: list[dict[str, Any]] = []
    offset = 32
    frame_index = 0
    while offset + 24 + frame_page_size <= len(wal):
        header = wal[offset : offset + 24]
        data_start = offset + 24
        out.append(
            {
                "source_kind": "wal-frame",
                "origin": origin,
                "page_number": int.from_bytes(header[0:4], "big"),
                "frame_index": frame_index,
                "offset": data_start,
                "blob": wal[data_start : data_start + frame_page_size],
            }
        )
        offset = data_start + frame_page_size
        frame_index += 1
    return out
