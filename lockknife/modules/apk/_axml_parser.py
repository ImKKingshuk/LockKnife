from __future__ import annotations

import math
import pathlib
import re
import struct
import xml.etree.ElementTree as ET
import zipfile

from defusedxml.ElementTree import fromstring

MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_STRINGS = 100_000
MAX_DEPTH = 256
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z")
ET.register_namespace("android", "http://schemas.android.com/apk/res/android")


def _decode_string_pool(chunk: bytes) -> list[str]:
    if len(chunk) < 28:
        raise ValueError("Truncated string pool")
    header_size = struct.unpack_from("<H", chunk, 2)[0]
    count, styles, flags, start, styles_start = struct.unpack_from("<IIIII", chunk, 8)
    offsets_end = header_size + (count + styles) * 4
    end = styles_start or len(chunk)
    if count > MAX_STRINGS or not (28 <= header_size <= offsets_end <= start <= end <= len(chunk)):
        raise ValueError("Invalid string pool bounds")
    strings = []

    def length(pos: int, *, utf8: bool) -> tuple[int, int]:
        width, high, mask = (1, 0x80, 0x7F) if utf8 else (2, 0x8000, 0x7FFF)
        if pos + width > end:
            raise ValueError("Truncated string length")
        first = int.from_bytes(chunk[pos : pos + width], "little")
        pos += width
        if first & high:
            if pos + width > end:
                raise ValueError("Truncated extended string length")
            second = int.from_bytes(chunk[pos : pos + width], "little")
            pos += width
            first = ((first & mask) << (width * 8)) | second
        return first, pos

    for i in range(count):
        offset = struct.unpack_from("<I", chunk, header_size + i * 4)[0]
        pos = start + offset
        if not start <= pos < end:
            raise ValueError("String offset outside pool")
        utf8 = bool(flags & 0x100)
        chars, pos = length(pos, utf8=utf8)
        if utf8:
            size, pos = length(pos, utf8=True)
            width, encoding = 1, "utf-8"
        else:
            size, width, encoding = chars * 2, 2, "utf-16le"
        if pos + size + width > end or chunk[pos + size : pos + size + width] != b"\0" * width:
            raise ValueError("Truncated or unterminated string")
        value = chunk[pos : pos + size].decode(encoding)
        if utf8 and len(value.encode("utf-16le")) // 2 != chars:
            raise ValueError("Incorrect string character length")
        strings.append(value)
    return strings


def _typed_value(kind: int, data: int, string_at) -> str:
    if kind == 0x03:
        return string_at(data)
    if kind == 0x12:
        return "true" if data else "false"
    if kind == 0x10:
        return str(data if data < 0x80000000 else data - 0x100000000)
    if kind == 0x11:
        return f"0x{data:x}"
    if kind in (0x01, 0x02):
        return f"{'@' if kind == 0x01 else '?'}0x{data:08x}"
    if kind == 0x04:
        value = struct.unpack("<f", struct.pack("<I", data))[0]
        if not math.isfinite(value):
            raise ValueError("Non-finite float attribute")
        return str(value)
    if kind in (0x05, 0x06):
        # Android complex values use a signed 24-bit mantissa and a two-bit radix.
        mantissa = data & 0xFFFFFF00
        if mantissa >= 0x80000000:
            mantissa -= 0x100000000
        value = mantissa * (1 / 256, 1 / 32768, 1 / 8388608, 1 / 2147483648)[(data >> 4) & 3]
        units = ("px", "dp", "sp", "pt", "in", "mm") if kind == 0x05 else ("%", "%p")
        unit = data & 0xF
        if unit >= len(units):
            raise ValueError("Invalid complex attribute unit")
        if kind == 0x06:
            value *= 100
        return f"{value:g}{units[unit]}"
    if 0x1C <= kind <= 0x1F:
        width = (8, 6, 4, 3)[kind - 0x1C]
        return f"#{data & ((1 << (width * 4)) - 1):0{width}x}"
    if kind == 0:
        return ""
    raise ValueError(f"Unsupported attribute type: {kind}")


def parse_axml_to_xml(data: bytes) -> str:
    """Decode a bounded, structurally valid Android binary or plain XML document."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("Manifest exceeds size limit")
    if data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"<"):
        text = data.decode("utf-8-sig")
        fromstring(text)
        return text
    if len(data) < 8:
        raise ValueError("Data too short for Android Binary XML")
    kind, header, size = struct.unpack_from("<HHI", data)
    if kind != RES_XML_TYPE or header != 8 or size != len(data):
        raise ValueError("Invalid binary XML header")

    strings: list[str] = []
    namespaces: list[tuple[int, int]] = []
    stack: list[ET.Element] = []
    root: ET.Element | None = None
    pool_seen = False

    def string_at(index: int) -> str:
        if not 0 <= index < len(strings):
            raise ValueError("Invalid string index")
        return strings[index]

    def name_at(ns: int, index: int) -> str:
        name = string_at(index)
        if not _NAME.fullmatch(name):
            raise ValueError("Invalid XML name")
        return name if ns == 0xFFFFFFFF else f"{{{string_at(ns)}}}{name}"

    pos = header
    while pos < size:
        if pos + 8 > size:
            raise ValueError("Truncated XML chunk")
        c_type, c_header, c_size = struct.unpack_from("<HHI", data, pos)
        if not 8 <= c_header <= c_size <= size - pos:
            raise ValueError("Invalid XML chunk bounds")
        chunk = data[pos : pos + c_size]
        if c_type == RES_STRING_POOL_TYPE:
            if pool_seen or root is not None:
                raise ValueError("Duplicate or misplaced string pool")
            strings = _decode_string_pool(chunk)
            pool_seen = True
        elif c_type == RES_XML_RESOURCE_MAP_TYPE:
            if c_header != 8 or (c_size - c_header) % 4:
                raise ValueError("Invalid XML resource map")
        elif c_type in (RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE):
            if c_header != 16 or c_size != 24:
                raise ValueError("Invalid namespace chunk")
            prefix, uri = struct.unpack_from("<II", chunk, 16)
            if prefix != 0xFFFFFFFF:
                value = string_at(prefix)
                if value and not _NAME.fullmatch(value):
                    raise ValueError("Invalid namespace prefix")
            string_at(uri)
            if c_type == RES_XML_START_NAMESPACE_TYPE:
                namespaces.append((prefix, uri))
            elif not namespaces or namespaces.pop() != (prefix, uri):
                raise ValueError("Unbalanced namespace")
        elif c_type == RES_XML_START_ELEMENT_TYPE:
            if c_header != 16 or c_size < 36 or len(stack) >= MAX_DEPTH:
                raise ValueError("Invalid start element")
            ns, name, start, stride, count = struct.unpack_from("<IIHHH", chunk, 16)
            offset = 16 + start
            if start < 20 or stride < 20 or offset + count * stride > c_size:
                raise ValueError("Invalid attribute bounds")
            element = ET.Element(name_at(ns, name))
            for i in range(count):
                ans, aname, raw, vsize, reserved, vtype, value = struct.unpack_from(
                    "<IIIHBBI", chunk, offset + i * stride
                )
                if vsize != 8 or reserved:
                    raise ValueError("Invalid attribute value header")
                key = name_at(ans, aname)
                if key in element.attrib:
                    raise ValueError("Duplicate attribute")
                element.set(
                    key,
                    string_at(raw) if raw != 0xFFFFFFFF else _typed_value(vtype, value, string_at),
                )
            if stack:
                stack[-1].append(element)
            elif root is None:
                root = element
            else:
                raise ValueError("Multiple XML roots")
            stack.append(element)
        elif c_type == RES_XML_END_ELEMENT_TYPE:
            if c_header != 16 or c_size != 24:
                raise ValueError("Invalid end element")
            ns, name = struct.unpack_from("<II", chunk, 16)
            if not stack or stack.pop().tag != name_at(ns, name):
                raise ValueError("Unbalanced XML element")
        elif c_type == RES_XML_CDATA_TYPE:
            if c_header != 16 or c_size != 28 or not stack:
                raise ValueError("Invalid XML text chunk")
            text = string_at(struct.unpack_from("<I", chunk, 16)[0])
            parent = stack[-1]
            if len(parent):
                parent[-1].tail = (parent[-1].tail or "") + text
            else:
                parent.text = (parent.text or "") + text
        else:
            raise ValueError(f"Unsupported XML chunk: {c_type}")
        pos += c_size
    if root is None or stack or namespaces:
        raise ValueError("Incomplete XML document")
    result = ET.tostring(root, encoding="unicode")
    fromstring(result)
    return '<?xml version="1.0" encoding="utf-8"?>\n' + result


def extract_manifest_xml_from_apk(apk_path: pathlib.Path) -> str:
    """Extract a single bounded manifest from an APK."""
    with zipfile.ZipFile(apk_path) as archive:
        matches = [
            entry for entry in archive.infolist() if entry.filename.lower() == "androidmanifest.xml"
        ]
        if len(matches) != 1:
            raise ValueError("APK must contain exactly one AndroidManifest.xml")
        entry = matches[0]
        if entry.file_size > MAX_MANIFEST_BYTES:
            raise ValueError("Manifest exceeds size limit")
        with archive.open(entry) as handle:
            data = handle.read(MAX_MANIFEST_BYTES + 1)
        return parse_axml_to_xml(data)
