from __future__ import annotations

import json
import pathlib
import zipfile
from typing import Any, cast


def extract_dex_headers_impl(
    apk_path: pathlib.Path, *, lockknife_core_module: Any
) -> list[dict[str, Any]]:
    headers: list[dict[str, Any]] = []
    with zipfile.ZipFile(apk_path, "r") as archive:
        for name in archive.namelist():
            if name.endswith(".dex"):
                # Header inspection only needs the first 112 bytes, not the full DEX.
                with archive.open(name) as handle:
                    dex = handle.read(112)
                try:
                    header_json = lockknife_core_module.parse_dex_header_json(dex)
                except ValueError as exc:
                    headers.append({"file": name, "error": str(exc)})
                    continue
                headers.append(
                    {"file": name, "header": cast(dict[str, Any], json.loads(header_json))}
                )
    return headers
