from __future__ import annotations

import pathlib
import shutil

_temp_paths: set[pathlib.Path] = set()


def register_temp_path(path: pathlib.Path) -> None:
    _temp_paths.add(path)


def unregister_temp_path(path: pathlib.Path) -> None:
    _temp_paths.discard(path)


def cleanup_all() -> None:
    for path in list(_temp_paths):
        try:
            shutil.rmtree(path, ignore_errors=True)
        finally:
            _temp_paths.discard(path)
