from __future__ import annotations

import pathlib
import shutil
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
    normalized = validate_user_path_text(member_name, label="archive member").replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute():
        raise ValueError(f"Unsafe archive member path: {member_name}")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"Unsafe archive member path: {member_name}")
    if pure.parts and ":" in pure.parts[0]:
        raise ValueError(f"Unsafe archive member path: {member_name}")
    return pure


def safe_extract_zip(archive: zipfile.ZipFile, output_dir: pathlib.Path) -> list[pathlib.Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[pathlib.Path] = []
    for info in archive.infolist():
        member_path = validate_archive_member(info.filename)
        destination = ensure_child_path(
            output_dir, output_dir / pathlib.Path(*member_path.parts), label="archive member"
        )
        if info.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            extracted.append(destination)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info, "r") as source, destination.open("wb") as handle:
            shutil.copyfileobj(source, handle)
        extracted.append(destination)
    return extracted
