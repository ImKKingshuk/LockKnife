from __future__ import annotations

import pathlib
import struct
import zipfile

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB8 = 0x1D
TYPE_INT_COLOR_ARGB4 = 0x1E
TYPE_INT_COLOR_RGB4 = 0x1F

DIMENSION_UNITS = ["px", "dp", "sp", "pt", "in", "mm"]
FRACTION_UNITS = ["%", "%p"]


def _escape_xml_attr(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _decode_string_pool(data: bytes, chunk_offset: int) -> list[str]:
    scount, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", data, chunk_offset + 8
    )
    is_utf8 = bool(flags & (1 << 8))
    offsets = [
        struct.unpack_from("<I", data, chunk_offset + 28 + i * 4)[0]
        for i in range(scount)
    ]
    pool_base = chunk_offset + strings_start
    strings: list[str] = []

    for off in offsets:
        str_pos = pool_base + off
        if str_pos >= len(data):
            strings.append("")
            continue
        if is_utf8:
            # UTF-8: skip UTF-16 character length (1 or 2 bytes)
            if str_pos >= len(data):
                strings.append("")
                continue
            b1 = data[str_pos]
            str_pos += 1
            if b1 & 0x80 and str_pos < len(data):
                str_pos += 1

            if str_pos >= len(data):
                strings.append("")
                continue
            b2 = data[str_pos]
            str_pos += 1
            u8len = b2
            if b2 & 0x80 and str_pos < len(data):
                u8len = ((b2 & 0x7F) << 8) | data[str_pos]
                str_pos += 1

            s_bytes = data[str_pos : str_pos + u8len]
            strings.append(s_bytes.decode("utf-8", errors="replace"))
        else:
            # UTF-16LE
            if str_pos + 2 > len(data):
                strings.append("")
                continue
            u16len = struct.unpack_from("<H", data, str_pos)[0]
            str_pos += 2
            if u16len & 0x8000:
                if str_pos + 2 > len(data):
                    strings.append("")
                    continue
                next_part = struct.unpack_from("<H", data, str_pos)[0]
                u16len = ((u16len & 0x7FFF) << 16) | next_part
                str_pos += 2

            byte_len = u16len * 2
            s_bytes = data[str_pos : str_pos + byte_len]
            strings.append(s_bytes.decode("utf-16le", errors="replace"))

    return strings


def parse_axml_to_xml(data: bytes) -> str:
    """Decode raw bytes of an AndroidManifest.xml (binary AXML or plain XML) to XML string."""
    stripped = data.strip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<"):
        return data.decode("utf-8", errors="replace")

    if len(data) < 8:
        raise ValueError("Data too short for Android Binary XML")

    chunk_type, header_size, _chunk_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != RES_XML_TYPE:
        # If not RES_XML_TYPE, attempt plain UTF-8 decoding fallback
        return data.decode("utf-8", errors="replace")

    pos = header_size
    strings: list[str] = []
    lines: list[str] = []
    ns_map: dict[str, str] = {}  # uri -> prefix

    while pos < len(data):
        if pos + 8 > len(data):
            break
        c_type, _c_hsize, c_size = struct.unpack_from("<HHI", data, pos)
        if c_size <= 0:
            break
        chunk_end = pos + c_size

        if c_type == RES_STRING_POOL_TYPE:
            strings = _decode_string_pool(data, pos)

        elif c_type == RES_XML_START_NAMESPACE_TYPE:
            if pos + 24 <= len(data):
                _line, _comment, prefix_idx, uri_idx = struct.unpack_from(
                    "<IIII", data, pos + 8
                )
                prefix = strings[prefix_idx] if 0 <= prefix_idx < len(strings) else ""
                uri = strings[uri_idx] if 0 <= uri_idx < len(strings) else ""
                if uri:
                    ns_map[uri] = prefix

        elif c_type == RES_XML_START_ELEMENT_TYPE:
            if pos + 28 <= len(data):
                _ns_idx, name_idx, attr_start, attr_size, attr_count = (
                    struct.unpack_from("<IIHHH", data, pos + 16)
                )
                tag_name = (
                    strings[name_idx] if 0 <= name_idx < len(strings) else "unknown"
                )

                attrs: list[str] = []
                attr_offset = pos + 16 + attr_start
                for a_idx in range(attr_count):
                    curr = attr_offset + a_idx * attr_size
                    if curr + 20 > len(data):
                        break
                    a_ns, a_name, a_raw, _val_size, _val_res0, val_type, val_data = (
                        struct.unpack_from("<IIIHBBI", data, curr)
                    )
                    aname = strings[a_name] if 0 <= a_name < len(strings) else "attr"
                    ans_uri = strings[a_ns] if 0 <= a_ns < len(strings) else None
                    prefix = ns_map.get(ans_uri) if ans_uri else None
                    if not prefix and ans_uri and "android" in ans_uri.lower():
                        prefix = "android"
                    full_name = f"{prefix}:{aname}" if prefix else aname

                    # Determine attribute value representation
                    if a_raw != 0xFFFFFFFF and 0 <= a_raw < len(strings):
                        val_str = strings[a_raw]
                    elif val_type == TYPE_STRING and 0 <= val_data < len(strings):
                        val_str = strings[val_data]
                    elif val_type == TYPE_INT_BOOLEAN:
                        val_str = "true" if val_data != 0 else "false"
                    elif val_type in (TYPE_INT_DEC, TYPE_INT_HEX):
                        val_str = str(val_data)
                    elif val_type == TYPE_REFERENCE:
                        val_str = f"@0x{val_data:08x}"
                    elif val_type in (
                        TYPE_INT_COLOR_ARGB8,
                        TYPE_INT_COLOR_RGB8,
                        TYPE_INT_COLOR_ARGB4,
                        TYPE_INT_COLOR_RGB4,
                    ):
                        val_str = f"#{val_data:08x}"
                    elif val_type == TYPE_DIMENSION:
                        unit = DIMENSION_UNITS[val_data & 0x0F] if (val_data & 0x0F) < len(DIMENSION_UNITS) else ""
                        val_str = f"{val_data >> 8}{unit}"
                    elif val_type == TYPE_FRACTION:
                        unit = FRACTION_UNITS[val_data & 0x0F] if (val_data & 0x0F) < len(FRACTION_UNITS) else ""
                        val_str = f"{val_data >> 8}{unit}"
                    else:
                        val_str = str(val_data)

                    attrs.append(f'{full_name}="{_escape_xml_attr(val_str)}"')

                attr_str = (" " + " ".join(attrs)) if attrs else ""
                if tag_name == "manifest" and "xmlns:android" not in attr_str:
                    attr_str = (
                        ' xmlns:android="http://schemas.android.com/apk/res/android"'
                        + attr_str
                    )
                lines.append(f"<{tag_name}{attr_str}>")

        elif c_type == RES_XML_END_ELEMENT_TYPE:
            if pos + 24 <= len(data):
                _ns_idx, name_idx = struct.unpack_from("<II", data, pos + 16)
                tag_name = (
                    strings[name_idx] if 0 <= name_idx < len(strings) else "unknown"
                )
                lines.append(f"</{tag_name}>")

        elif c_type == RES_XML_CDATA_TYPE:
            if pos + 20 <= len(data):
                data_idx = struct.unpack_from("<I", data, pos + 16)[0]
                if 0 <= data_idx < len(strings):
                    lines.append(_escape_xml_attr(strings[data_idx]))

        pos = chunk_end

    return '<?xml version="1.0" encoding="utf-8"?>\n' + "\n".join(lines)


def extract_manifest_xml_from_apk(apk_path: pathlib.Path) -> str:
    """Extract and decode AndroidManifest.xml from an APK file."""
    with zipfile.ZipFile(apk_path, "r") as archive:
        for name in archive.namelist():
            if name.lower() == "androidmanifest.xml":
                raw_bytes = archive.read(name)
                return parse_axml_to_xml(raw_bytes)
    raise FileNotFoundError(f"AndroidManifest.xml not found in {apk_path}")
