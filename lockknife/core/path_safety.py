from __future__ import annotations

import os
import pathlib
import stat
import tempfile
import zipfile
from pathlib import PurePosixPath


def validate_user_path_text(raw: str, *, label: str = "path") -> str:
    text = raw.strip()
    if not text:
        raise ValueError(f"{label} cannot be empty")
    if any(ord(ch) < 32 for ch in text):
        raise ValueError(f"{label} contains control characters")
    return text


def validate_relative_component(raw: str, *, label: str) -> str:
    text = validate_user_path_text(raw, label=label)
    if text in {".", ".."}:
        raise ValueError(f"{label} cannot be '.' or '..'")
    if "/" in text or "\\" in text:
        raise ValueError(f"{label} must not contain path separators")
    return text


def ensure_child_path(
    base_dir: pathlib.Path, target_path: pathlib.Path, *, label: str = "path"
) -> pathlib.Path:
    base_resolved = base_dir.resolve()
    target_resolved = target_path.resolve()
    try:
        target_resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the expected base directory") from exc
    return target_resolved


def validate_archive_member(member_name: str) -> PurePosixPath:
    stripped = member_name.strip()
    if stripped.startswith(("/", "\\")):
        raise ValueError(f"Unsafe archive member path: {member_name}")
    if len(stripped) >= 2 and stripped[1] == ":" and stripped[0].isalpha():
        raise ValueError(f"Unsafe archive member path: {member_name}")
    if ".." in stripped:
        raise ValueError(f"Unsafe archive member path: {member_name}")
    normalized = validate_user_path_text(member_name, label="archive member").replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute():
        raise ValueError(f"Unsafe archive member path: {member_name}")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"Unsafe archive member path: {member_name}")
    if pure.parts and ":" in pure.parts[0]:
        raise ValueError(f"Unsafe archive member path: {member_name}")
    return pure


def safe_extract_zip(
    archive: zipfile.ZipFile,
    output_dir: pathlib.Path,
    *,
    max_members: int = 10_000,
    max_total_bytes: int = 512 * 1024 * 1024,
    max_member_bytes: int = 128 * 1024 * 1024,
    max_compression_ratio: float = 1000.0,
) -> list[pathlib.Path]:
    """Extract bounded regular files without overwriting existing evidence.

    Validate the entire inventory before writing. Bounds are checked again while
    streaming because archive metadata is not a trusted size guarantee.
    """
    if min(max_members, max_total_bytes, max_member_bytes, max_compression_ratio) <= 0:
        raise ValueError("Archive extraction limits must be positive")
    members = archive.infolist()
    if len(members) > max_members:
        raise ValueError("Archive member count exceeds extraction limit")
    destinations: list[tuple[zipfile.ZipInfo, pathlib.Path]] = []
    names: dict[str, bool] = {}
    total = 0
    for info in members:
        member = validate_archive_member(info.filename)
        name = member.as_posix().casefold()
        if name in names:
            raise ValueError(f"Duplicate archive destination: {info.filename}")
        names[name] = info.is_dir()
        mode = stat.S_IFMT(info.external_attr >> 16)
        if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise ValueError(f"Unsupported archive member type: {info.filename}")
        if info.flag_bits & 1:
            raise ValueError(f"Encrypted archive member is unsupported: {info.filename}")
        total += info.file_size
        if info.file_size > max_member_bytes or total > max_total_bytes:
            raise ValueError("Archive size exceeds extraction limit")
        if info.file_size / max(info.compress_size, 1) > max_compression_ratio:
            raise ValueError("Archive compression ratio exceeds extraction limit")
        raw_destination = output_dir / pathlib.Path(*member.parts)
        for ancestor in (raw_destination, *raw_destination.parents):
            if ancestor == output_dir:
                break
            if ancestor.is_symlink():
                raise ValueError(f"Archive destination contains a symbolic link: {info.filename}")
        destination = ensure_child_path(output_dir, raw_destination, label="archive member")
        if destination.exists() and (not info.is_dir() or not destination.is_dir()):
            raise FileExistsError(f"Archive destination already exists: {destination}")
        destinations.append((info, destination))
    for name in names:
        for parent in PurePosixPath(name).parents:
            if parent.as_posix() in names and not names[parent.as_posix()]:
                raise ValueError(f"Archive file/directory conflict: {name}")
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[pathlib.Path] = []
    actual_total = 0
    for info, destination in destinations:
        if info.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            extracted.append(destination)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary: pathlib.Path | None = None
        try:
            with (
                archive.open(info, "r") as source,
                tempfile.NamedTemporaryFile(
                    dir=destination.parent, prefix=".extract-", delete=False
                ) as handle,
            ):
                temporary = pathlib.Path(handle.name)
                member_bytes = 0
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    member_bytes += len(chunk)
                    actual_total += len(chunk)
                    if member_bytes > max_member_bytes or actual_total > max_total_bytes:
                        raise ValueError("Archive size exceeds extraction limit")
                    handle.write(chunk)
                if member_bytes != info.file_size:
                    raise ValueError(f"Archive member size mismatch: {info.filename}")
                handle.flush()
                os.fsync(handle.fileno())
            # Atomic exclusive publication also protects against late file creation.
            os.link(temporary, destination)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        extracted.append(destination)
    return extracted
