from __future__ import annotations

import json
import pathlib
import zipfile

import pytest

from scripts.verify_distribution import verify_wheel_metadata


def _wheel(path: pathlib.Path, *, missing: str = "", version: str = "1.2.0") -> pathlib.Path:
    entries = {
        "lockknife/__init__.py": "",
        "lockknife_headless_cli/main.py": "",
        "lockknife_headless_cli/actions/catalog.json": json.dumps({"modules": [{"id": "core"}]}),
        "lockknife/lockknife_core.pyi": "",
        "lockknife/lockknife_core.abi3.so": "native fixture",
        "lockknife.dist-info/METADATA": f"Name: lockknife\nVersion: {version}\n",
        "lockknife.dist-info/entry_points.txt": "[console_scripts]\nlockknife=lockknife_headless_cli.main:cli\n",
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in entries.items():
            if name != missing:
                archive.writestr(name, value)
    return path


def test_distribution_metadata_and_version(tmp_path: pathlib.Path) -> None:
    wheel = _wheel(tmp_path / "wheel.whl")
    verify_wheel_metadata(wheel, "v1.2.0")
    with pytest.raises(ValueError, match="version"):
        verify_wheel_metadata(wheel, "v1.3.0")


@pytest.mark.parametrize(
    "missing",
    [
        "lockknife_headless_cli/actions/catalog.json",
        "lockknife/lockknife_core.abi3.so",
        "lockknife/lockknife_core.pyi",
        "lockknife.dist-info/METADATA",
        "lockknife.dist-info/entry_points.txt",
    ],
)
def test_distribution_rejects_incomplete_wheels(tmp_path: pathlib.Path, missing: str) -> None:
    with pytest.raises(ValueError):
        verify_wheel_metadata(_wheel(tmp_path / "wheel.whl", missing=missing))
