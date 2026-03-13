from __future__ import annotations

import pathlib
import re
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
CARGO = ROOT / "rust" / "Cargo.toml"
INIT = ROOT / "lockknife" / "__init__.py"


def _read_pyproject_version() -> str:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _replace_version(text: str, pattern: str, version: str) -> str:
    return re.sub(pattern, f'\\1"{version}"', text, count=1, flags=re.MULTILINE)


def sync_versions() -> None:
    version = _read_pyproject_version()
    cargo_text = CARGO.read_text(encoding="utf-8")
    cargo_text = _replace_version(cargo_text, r'(^version\s*=\s*)".*"$', version)
    CARGO.write_text(cargo_text, encoding="utf-8")

    init_text = INIT.read_text(encoding="utf-8")
    init_text = _replace_version(init_text, r'^(__version__\s*=\s*)".*"$', version)
    INIT.write_text(init_text, encoding="utf-8")


def check_versions() -> int:
    version = _read_pyproject_version()
    cargo_text = CARGO.read_text(encoding="utf-8")
    init_text = INIT.read_text(encoding="utf-8")

    cargo_match = re.search(r'^version\s*=\s*"([^"]+)"$', cargo_text, flags=re.MULTILINE)
    init_match = re.search(r'^__version__\s*=\s*"([^"]+)"$', init_text, flags=re.MULTILINE)
    cargo_ver = cargo_match.group(1) if cargo_match else ""
    init_ver = init_match.group(1) if init_match else ""

    ok = version == cargo_ver == init_ver
    return 0 if ok else 1


def main() -> None:
    cmd = (sys.argv[1] if len(sys.argv) > 1 else "check").lower()
    if cmd == "sync":
        sync_versions()
        return
    if cmd == "check":
        raise SystemExit(check_versions())
    raise SystemExit(2)


if __name__ == "__main__":
    main()
