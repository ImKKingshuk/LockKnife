from __future__ import annotations

import pathlib
import zipfile
from pathlib import PurePosixPath
from typing import Any

from lockknife.core.path_safety import safe_extract_zip


def archive_inventory(apk_path: pathlib.Path) -> dict[str, Any]:
    dex_files: list[str] = []
    native_libs: list[str] = []
    signer_files: list[str] = []
    asset_files = 0
    top_level_entries: set[str] = set()
    all_entries: list[str] = []
    abi_families: set[str] = set()
    with zipfile.ZipFile(apk_path, "r") as archive:
        for name in archive.namelist():
            all_entries.append(name)
            parts = PurePosixPath(name).parts
            if parts:
                top_level_entries.add(parts[0])
            if name.endswith(".dex"):
                dex_files.append(name)
            elif name.startswith("lib/") and name.endswith(".so"):
                native_libs.append(name)
                if len(parts) >= 2 and parts[1]:
                    abi_families.add(parts[1])
            elif name.startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC")):
                signer_files.append(name)
            elif name.startswith("assets/"):
                asset_files += 1
    return {
        "file_count": len(all_entries),
        "entry_preview": sorted(all_entries)[:25],
        "top_level_entries": sorted(top_level_entries),
        "dex_files": sorted(dex_files),
        "dex_count": len(dex_files),
        "native_libraries": sorted(native_libs),
        "native_library_count": len(native_libs),
        "abi_families": sorted(abi_families),
        "meta_inf_signers": sorted(signer_files),
        "asset_file_count": asset_files,
    }


def unpack_archive(apk_path: pathlib.Path, output_dir: pathlib.Path) -> dict[str, Any]:
    with zipfile.ZipFile(apk_path, "r") as archive:
        extracted_paths = safe_extract_zip(archive, output_dir)
    inventory = archive_inventory(apk_path)
    return {
        "name": "unpack",
        "status": "completed",
        "output_dir": str(output_dir),
        "extracted_path_count": len(extracted_paths),
        "file_count": inventory.get("file_count") or 0,
        "dex_count": inventory.get("dex_count") or 0,
        "native_library_count": inventory.get("native_library_count") or 0,
        "asset_file_count": inventory.get("asset_file_count") or 0,
    }


def output_directory_overview(output_dir: pathlib.Path) -> dict[str, Any]:
    if not output_dir.exists():
        return {"directory_count": 0, "file_count": 0, "preview": []}
    file_count = 0
    directory_count = 0
    preview: list[str] = []
    for path in sorted(output_dir.rglob("*")):
        rel = str(path.relative_to(output_dir))
        if path.is_dir():
            directory_count += 1
        else:
            file_count += 1
        if len(preview) < 20:
            preview.append(rel)
    return {
        "directory_count": directory_count,
        "file_count": file_count,
        "preview": preview,
    }
