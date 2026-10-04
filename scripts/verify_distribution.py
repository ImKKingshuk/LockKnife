"""Verify a release artifact without importing the source checkout."""

from __future__ import annotations

import argparse
import configparser
import email.parser
import json
import pathlib
import subprocess
import sys
import tempfile
import zipfile


def verify_wheel_metadata(path: pathlib.Path, expected_version: str = "") -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise ValueError("Wheel must contain exactly one package metadata file")
        metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_names[0]))
        if metadata["Name"] != "lockknife":
            raise ValueError("Wheel does not contain LockKnife")
        if expected_version and metadata["Version"] != expected_version.removeprefix("v"):
            raise ValueError("Wheel version does not match the release tag")
        entry_points = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        if len(entry_points) != 1:
            raise ValueError("Wheel must contain exactly one entry-point manifest")
        config = configparser.ConfigParser()
        config.read_string(archive.read(entry_points[0]).decode("utf-8"))
        if config.get("console_scripts", "lockknife") != "lockknife_headless_cli.main:cli":
            raise ValueError("Wheel has an invalid console entry point")
        for required in (
            "lockknife/__init__.py",
            "lockknife_headless_cli/main.py",
            "lockknife_headless_cli/actions/catalog.json",
            "lockknife/lockknife_core.pyi",
        ):
            if required not in names:
                raise ValueError(f"Wheel is missing {required}")
        if not any(
            name.startswith("lockknife/lockknife_core") and name.endswith((".so", ".pyd"))
            for name in names
        ):
            raise ValueError("Wheel is missing the native extension")
        catalog = json.loads(archive.read("lockknife_headless_cli/actions/catalog.json"))
        if not catalog:
            raise ValueError("Wheel action catalog is empty")


SMOKE_CODE = """
import hashlib
import importlib.metadata
import json
import sys
import click
from click.testing import CliRunner
import lockknife.lockknife_core as native
from lockknife_headless_cli.main import cli

assert native.sha256_hex(b'release-check') == hashlib.sha256(b'release-check').hexdigest()
version = importlib.metadata.version('lockknife')
if sys.argv[1]:
    assert version == sys.argv[1].removeprefix('v'), (version, sys.argv[1])
runner = CliRunner()
count = 0
def visit(command, path=()):
    global count
    result = runner.invoke(cli, ['--cli', *path, '--help'])
    assert result.exit_code == 0, (path, result.output, result.exception)
    count += 1
    if isinstance(command, click.Group):
        for name, child in command.commands.items():
            if not child.hidden:
                visit(child, (*path, name))
visit(cli)
result = runner.invoke(cli, ['--cli', 'actions', '--format', 'json'])
assert result.exit_code == 0, (result.output, result.exception)
catalog = json.loads(result.output)
assert catalog
print(f'Installed LockKnife {version}: native import, action catalog, and {count} command help pages passed.')
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=pathlib.Path)
    parser.add_argument("--metadata-only", action="store_true")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--expected-version", default="")
    args = parser.parse_args()
    artifact = args.artifact.resolve(strict=True)
    if artifact.suffix == ".whl":
        verify_wheel_metadata(artifact, args.expected_version)
    elif not artifact.name.endswith(".tar.gz") or args.metadata_only:
        parser.error("Expected a wheel or source distribution; metadata-only requires a wheel")
    if args.metadata_only:
        print(f"Wheel metadata passed: {artifact.name}. Native execution was not tested.")
        return 0
    with tempfile.TemporaryDirectory(prefix="lockknife-distribution-") as temporary:
        root = pathlib.Path(temporary)
        env = root / "venv"
        subprocess.run(["uv", "venv", "--python", args.python, str(env)], check=True)
        python = env / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run(["uv", "pip", "install", "--python", str(python), str(artifact)], check=True)
        subprocess.run(
            [str(python), "-I", "-c", SMOKE_CODE, args.expected_version], cwd=root, check=True
        )
        executable = env / ("Scripts/lockknife.exe" if sys.platform == "win32" else "bin/lockknife")
        subprocess.run([str(executable), "--version"], cwd=root, check=True)
        subprocess.run([str(executable), "--cli", "--help"], cwd=root, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
