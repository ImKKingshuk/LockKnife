from __future__ import annotations

import pathlib
import shutil

_temp_paths: set[pathlib.Path] = set()
_terminal_cleanup_callbacks: list[callable[[], None]] = []


def register_temp_path(path: pathlib.Path) -> None:
    _temp_paths.add(path)


def unregister_temp_path(path: pathlib.Path) -> None:
    _temp_paths.discard(path)


def register_terminal_cleanup(callback: callable[[], None]) -> None:
    """Register a callback to restore terminal state on cleanup."""
    _terminal_cleanup_callbacks.append(callback)


def cleanup_all() -> None:
    # Restore terminal first
    for callback in _terminal_cleanup_callbacks:
        try:
            callback()
        except Exception:
            pass  # Best effort cleanup
    
    # Then clean up temp paths
    for path in list(_temp_paths):
        try:
            shutil.rmtree(path, ignore_errors=True)
        finally:
            _temp_paths.discard(path)
