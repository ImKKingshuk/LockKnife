from __future__ import annotations

import dataclasses
import pathlib
import struct

from lockknife.core.device import DeviceManager
from lockknife.core.logging import get_logger
from lockknife.core.security import secure_temp_dir

log = get_logger()


@dataclasses.dataclass(frozen=True)
class MediaFile:
    path: str
    size: int
    kind: str | None = None
    gps_lat: float | None = None
    gps_lon: float | None = None


def _read_u16(data: bytes, off: int, endian: str) -> int:
    fmt = "<H" if endian == "I" else ">H"
    return int(struct.unpack_from(fmt, data, off)[0])


def _read_u32(data: bytes, off: int, endian: str) -> int:
    fmt = "<I" if endian == "I" else ">I"
    return int(struct.unpack_from(fmt, data, off)[0])


def _read_rational(data: bytes, off: int, endian: str) -> float | None:
    fmt = "<II" if endian == "I" else ">II"
    num, den = struct.unpack_from(fmt, data, off)
    if den == 0:
        return None
    return float(num) / float(den)


def _parse_exif_gps(jpeg_bytes: bytes) -> tuple[float | None, float | None]:
    i = 0
    if not jpeg_bytes.startswith(b"\xff\xd8"):
        return None, None
    i = 2
    while i + 4 <= len(jpeg_bytes):
        if jpeg_bytes[i] != 0xFF:
            break
        marker = jpeg_bytes[i + 1]
        i += 2
        if marker == 0xD9 or marker == 0xDA:
            break
        if i + 2 > len(jpeg_bytes):
            break
        seg_len = int.from_bytes(jpeg_bytes[i : i + 2], "big")
        seg_start = i + 2
        seg_end = seg_start + seg_len - 2
        if seg_end > len(jpeg_bytes):
            break
        if marker == 0xE1 and jpeg_bytes[seg_start : seg_start + 6] == b"Exif\x00\x00":
            exif = jpeg_bytes[seg_start + 6 : seg_end]
            if len(exif) < 8:
                return None, None
            endian = chr(exif[0])
            if endian not in {"I", "M"}:
                return None, None
            tiff_off = 0
            ifd0 = _read_u32(exif, 4, endian)
            if ifd0 + 2 > len(exif):
                return None, None
            n = _read_u16(exif, ifd0, endian)
            gps_ptr: int | None = None
            for idx in range(n):
                ent = ifd0 + 2 + idx * 12
                if ent + 12 > len(exif):
                    break
                tag = _read_u16(exif, ent, endian)
                typ = _read_u16(exif, ent + 2, endian)
                cnt = _read_u32(exif, ent + 4, endian)
                val_off = ent + 8
                val = _read_u32(exif, val_off, endian)
                if tag == 0x8825 and typ == 4 and cnt == 1:
                    gps_ptr = val
                    break
            if gps_ptr is None or gps_ptr + 2 > len(exif):
                return None, None
            gn = _read_u16(exif, gps_ptr, endian)
            gps_lat_ref = None
            gps_lon_ref = None
            gps_lat = None
            gps_lon = None
            for idx in range(gn):
                ent = gps_ptr + 2 + idx * 12
                if ent + 12 > len(exif):
                    break
                tag = _read_u16(exif, ent, endian)
                typ = _read_u16(exif, ent + 2, endian)
                cnt = _read_u32(exif, ent + 4, endian)
                val = _read_u32(exif, ent + 8, endian)
                if tag == 1 and typ == 2:
                    off = val if cnt > 4 else ent + 8
                    gps_lat_ref = (
                        exif[off : off + cnt].split(b"\x00")[0].decode("ascii", errors="ignore")
                    )
                if tag == 2 and typ == 5 and cnt == 3:
                    off = val
                    if off + 24 <= len(exif):
                        deg = _read_rational(exif, off, endian)
                        minu = _read_rational(exif, off + 8, endian)
                        sec = _read_rational(exif, off + 16, endian)
                        if deg is not None and minu is not None and sec is not None:
                            gps_lat = deg + minu / 60.0 + sec / 3600.0
                if tag == 3 and typ == 2:
                    off = val if cnt > 4 else ent + 8
                    gps_lon_ref = (
                        exif[off : off + cnt].split(b"\x00")[0].decode("ascii", errors="ignore")
                    )
                if tag == 4 and typ == 5 and cnt == 3:
                    off = val
                    if off + 24 <= len(exif):
                        deg = _read_rational(exif, off, endian)
                        minu = _read_rational(exif, off + 8, endian)
                        sec = _read_rational(exif, off + 16, endian)
                        if deg is not None and minu is not None and sec is not None:
                            gps_lon = deg + minu / 60.0 + sec / 3600.0
            if gps_lat is not None and gps_lat_ref in {"S"}:
                gps_lat = -gps_lat
            if gps_lon is not None and gps_lon_ref in {"W"}:
                gps_lon = -gps_lon
            return gps_lat, gps_lon
        i += seg_len
    return None, None


def extract_media_with_exif(
    devices: DeviceManager, serial: str, limit: int = 50
) -> list[MediaFile]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    has_root = devices.has_root(serial)

    with secure_temp_dir(prefix="lockknife-media-") as d:
        candidates = [
            "/sdcard/DCIM/Camera",
            "/sdcard/DCIM",
            "/sdcard/Pictures",
            "/sdcard/Movies",
            "/sdcard/Download",
        ]
        files: list[str] = []
        for base in candidates:
            cmd = f"ls -1t {_escape_path_for_sh(base)} 2>/dev/null | head -n {int(limit)}"
            if has_root:
                cmd = f'su -c "{cmd}"'
            try:
                listing = devices.shell(serial, cmd, timeout_s=30.0)
            except (DeviceError, TimeoutError, OSError) as e:
                log.debug("media_ls_failed", exc_info=True, serial=serial, base=base, error=str(e))
                continue
            for ln in listing.splitlines():
                name = ln.strip()
                if not name or name.endswith("/"):
                    continue
                files.append(f"{base.rstrip('/')}/{name}")

        seen = set()
        uniq = []
        for p in files:
            if p in seen:
                continue
            seen.add(p)
            uniq.append(p)
        files = uniq[:limit]
        out: list[MediaFile] = []
        for remote in files:
            name = pathlib.PurePosixPath(remote).name
            local = d / name
            try:
                devices.pull(serial, remote, local, timeout_s=90.0)
            except (DeviceError, TimeoutError, OSError) as e:
                log.debug("media_pull_failed", exc_info=True, serial=serial, remote=remote, error=str(e))
                continue
            if not local.exists():
                continue
            size = int(local.stat().st_size)
            gps_lat = None
            gps_lon = None
            if local.suffix.lower() in {".jpg", ".jpeg"}:
                gps_lat, gps_lon = _parse_exif_gps(local.read_bytes())
            kind = local.suffix.lower().lstrip(".") or None
            out.append(
                MediaFile(path=remote, size=size, kind=kind, gps_lat=gps_lat, gps_lon=gps_lon)
            )
        return out


def _escape_path_for_sh(p: str) -> str:
    return "'" + p.replace("'", "'\"'\"'") + "'"
