from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
CORE_CARGO = ROOT / "lockknife-core" / "Cargo.toml"
TUI_CARGO = ROOT / "lockknife-tui" / "Cargo.toml"
CARGO_LOCK = ROOT / "Cargo.lock"
UV_LOCK = ROOT / "uv.lock"
INIT = ROOT / "lockknife" / "__init__.py"


def _read_pyproject_version() -> str:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _replace_version(text: str, pattern: str, version: str, *, source: pathlib.Path) -> str:
    updated, count = re.subn(pattern, f'\\1"{version}"', text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f"could not locate version field in {source}")
    return updated


def _replace_lock_package_versions(
    text: str,
    package_names: set[str],
    version: str,
    *,
    source: pathlib.Path,
) -> str:
    sections = text.split("[[package]]")
    updated_names: set[str] = set()
    for index, section in enumerate(sections[1:], start=1):
        name_match = re.search(r'^name = "([^"]+)"$', section, flags=re.MULTILINE)
        if name_match is None or name_match.group(1) not in package_names:
            continue
        sections[index] = _replace_version(
            section,
            r'^(version\s*=\s*)"[^"]+"$',
            version,
            source=source,
        )
        updated_names.add(name_match.group(1))
    missing = package_names - updated_names
    if missing:
        raise ValueError(f"missing package entries in {source}: {', '.join(sorted(missing))}")
    return "[[package]]".join(sections)


def _package_version(path: pathlib.Path) -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return str(data["package"]["version"])


def _lock_package_versions(path: pathlib.Path, package_names: set[str]) -> dict[str, str]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return {
        str(package["name"]): str(package["version"])
        for package in data["package"]
        if package.get("name") in package_names
    }


def sync_versions() -> None:
    version = _read_pyproject_version()
    core_text = CORE_CARGO.read_text(encoding="utf-8")
    core_text = _replace_version(
        core_text,
        r'(^version\s*=\s*)"[^"]+"$',
        version,
        source=CORE_CARGO,
    )
    core_text = _replace_version(
        core_text,
        r'^(lockknife-tui\s*=\s*\{\s*version\s*=\s*)"[^"]+"',
        version,
        source=CORE_CARGO,
    )
    CORE_CARGO.write_text(core_text, encoding="utf-8")

    tui_text = TUI_CARGO.read_text(encoding="utf-8")
    tui_text = _replace_version(
        tui_text,
        r'(^version\s*=\s*)"[^"]+"$',
        version,
        source=TUI_CARGO,
    )
    TUI_CARGO.write_text(tui_text, encoding="utf-8")

    init_text = INIT.read_text(encoding="utf-8")
    init_text = _replace_version(
        init_text,
        r'^(__version__\s*=\s*)"[^"]+"$',
        version,
        source=INIT,
    )
    INIT.write_text(init_text, encoding="utf-8")

    cargo_lock_text = _replace_lock_package_versions(
        CARGO_LOCK.read_text(encoding="utf-8"),
        {"lockknife-core", "lockknife-tui"},
        version,
        source=CARGO_LOCK,
    )
    CARGO_LOCK.write_text(cargo_lock_text, encoding="utf-8")

    uv_lock_text = _replace_lock_package_versions(
        UV_LOCK.read_text(encoding="utf-8"),
        {"lockknife"},
        version,
        source=UV_LOCK,
    )
    UV_LOCK.write_text(uv_lock_text, encoding="utf-8")


def check_versions(expected_version: str | None = None) -> int:
    version = _read_pyproject_version()
    init_text = INIT.read_text(encoding="utf-8")
    init_match = re.search(r'^__version__\s*=\s*"([^"]+)"$', init_text, flags=re.MULTILINE)
    init_ver = init_match.group(1) if init_match else ""
    core_data = tomllib.loads(CORE_CARGO.read_text(encoding="utf-8"))
    core_version = str(core_data["package"]["version"])
    tui_dependency_version = str(core_data["dependencies"]["lockknife-tui"]["version"])
    tui_version = _package_version(TUI_CARGO)
    cargo_lock_versions = _lock_package_versions(CARGO_LOCK, {"lockknife-core", "lockknife-tui"})
    uv_lock_versions = _lock_package_versions(UV_LOCK, {"lockknife"})

    versions_match = all(
        candidate == version
        for candidate in (
            init_ver,
            core_version,
            tui_dependency_version,
            tui_version,
            cargo_lock_versions.get("lockknife-core", ""),
            cargo_lock_versions.get("lockknife-tui", ""),
            uv_lock_versions.get("lockknife", ""),
        )
    )
    expected = (expected_version or "").removeprefix("v")
    expected_matches = not expected or expected == version
    return 0 if versions_match and expected_matches else 1


def main() -> None:
    cmd = (sys.argv[1] if len(sys.argv) > 1 else "check").lower()
    if cmd == "sync":
        sync_versions()
        return
    if cmd == "check":
        expected_version = sys.argv[2] if len(sys.argv) > 2 else None
        raise SystemExit(check_versions(expected_version))
    raise SystemExit(2)


if __name__ == "__main__":
    main()
