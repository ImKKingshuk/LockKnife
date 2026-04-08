from __future__ import annotations

import pathlib
from collections import Counter
from typing import Any


def decode_protobuf_file(
    path: pathlib.Path, *, max_fields: int = 200, max_depth: int = 2
) -> dict[str, Any] | None:
    return decode_protobuf_blob(
        path.read_bytes(), source_file=str(path), max_fields=max_fields, max_depth=max_depth
    )


def decode_protobuf_blob(
    data: bytes,
    *,
    source_file: str | None = None,
    max_fields: int = 200,
    max_depth: int = 2,
) -> dict[str, Any] | None:
    decoded = _decode_message(data, offset=0, depth=0, max_fields=max_fields, max_depth=max_depth)
    if not decoded["fields"]:
        return None
    field_counts = Counter(int(field["field_number"]) for field in decoded["fields"])
    wire_type_counts = Counter(str(field["wire_type"]) for field in decoded["fields"])
    return {
        "source_file": source_file,
        "format": "protobuf-heuristic",
        "message_count": len(decoded["fields"]),
        "field_count": len(field_counts),
        "top_fields": [
            {"field_number": field_number, "count": count}
            for field_number, count in field_counts.most_common(8)
        ],
        "wire_type_counts": dict(sorted(wire_type_counts.items())),
        "nested_message_count": decoded["nested_message_count"],
        "string_field_count": decoded["string_field_count"],
        "messages": decoded["fields"][:20],
        "summary": {
            "consumed_bytes": decoded["consumed_bytes"],
            "input_size_bytes": len(data),
            "truncated": decoded["consumed_bytes"] < len(data),
        },
    }


def _decode_message(
    data: bytes,
    *,
    offset: int,
    depth: int,
    max_fields: int,
    max_depth: int,
) -> dict[str, Any]:
    cursor = offset
    fields: list[dict[str, Any]] = []
    nested_message_count = 0
    string_field_count = 0
    while cursor < len(data) and len(fields) < max_fields:
        field_offset = cursor
        key, next_cursor = _read_varint(data, cursor)
        if next_cursor <= cursor or key <= 0:
            break
        field_number = key >> 3
        wire_type = key & 0x07
        cursor = next_cursor
        entry: dict[str, Any] = {
            "field_number": field_number,
            "wire_type": wire_type,
            "offset": field_offset,
            "depth": depth,
        }
        if wire_type == 0:
            value, cursor = _read_varint(data, cursor)
            if cursor <= next_cursor:
                break
            entry["kind"] = "varint"
            entry["value"] = value
            entry["inference"] = _infer_varint(value)
        elif wire_type == 1:
            if cursor + 8 > len(data):
                break
            payload = data[cursor : cursor + 8]
            cursor += 8
            entry["kind"] = "fixed64"
            entry["preview"] = payload.hex()
        elif wire_type == 2:
            length, cursor = _read_varint(data, cursor)
            if cursor <= next_cursor or length < 0 or cursor + length > len(data):
                break
            payload = data[cursor : cursor + length]
            cursor += length
            entry["kind"] = "length-delimited"
            entry["length"] = length
            entry["preview"] = _bytes_preview(payload)
            decoded_text = _decode_utf8(payload)
            if decoded_text is not None:
                entry["text"] = decoded_text
                string_field_count += 1
            elif depth < max_depth and _looks_like_nested_message(payload):
                nested = _decode_message(
                    payload,
                    offset=0,
                    depth=depth + 1,
                    max_fields=min(80, max_fields),
                    max_depth=max_depth,
                )
                if nested["fields"]:
                    nested_message_count += 1 + int(nested["nested_message_count"])
                    string_field_count += int(nested["string_field_count"])
                    entry["nested_message"] = {
                        "field_count": len(nested["fields"]),
                        "messages": nested["fields"][:8],
                    }
        elif wire_type == 5:
            if cursor + 4 > len(data):
                break
            payload = data[cursor : cursor + 4]
            cursor += 4
            entry["kind"] = "fixed32"
            entry["preview"] = payload.hex()
        else:
            break
        fields.append(entry)
    return {
        "fields": fields,
        "consumed_bytes": cursor,
        "nested_message_count": nested_message_count,
        "string_field_count": string_field_count,
    }


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    cursor = offset
    while cursor < len(data) and shift <= 63:
        byte = data[cursor]
        value |= (byte & 0x7F) << shift
        cursor += 1
        if not (byte & 0x80):
            return value, cursor
        shift += 7
    return 0, offset


def _decode_utf8(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except Exception:
        return None
    normalized = "".join(ch for ch in text if ch.isprintable() or ch in "\t\n\r").strip()
    if not normalized:
        return None
    return normalized[:160]


def _looks_like_nested_message(data: bytes) -> bool:
    if len(data) < 2:
        return False
    key, next_cursor = _read_varint(data, 0)
    if next_cursor <= 0 or key <= 0:
        return False
    field_number = key >> 3
    wire_type = key & 0x07
    return field_number > 0 and wire_type in {0, 1, 2, 5}


def _infer_varint(value: int) -> str:
    if value in {0, 1}:
        return "bool-or-enum"
    if 1_000_000_000 <= value <= 4_102_444_800:
        return "timestamp-seconds"
    if 1_000_000_000_000 <= value <= 4_102_444_800_000:
        return "timestamp-milliseconds"
    if value <= 65_535:
        return "small-int-or-enum"
    return "varint"


def _bytes_preview(data: bytes) -> str:
    decoded = _decode_utf8(data)
    return decoded if decoded is not None else data[:16].hex()
