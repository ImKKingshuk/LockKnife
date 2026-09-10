#!/usr/bin/env python3
"""Fail safely when tracked repository content is unsuitable for a public upload."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

MAX_TRACKED_FILE_BYTES = 5 * 1024 * 1024

FORBIDDEN_NAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "google-services.json",
    "googleservice-info.plist",
    "secrets.json",
}
FORBIDDEN_SUFFIXES = {
    ".aab",
    ".apk",
    ".db",
    ".dex",
    ".dmp",
    ".dump",
    ".jks",
    ".key",
    ".kdbx",
    ".keystore",
    ".p12",
    ".pcap",
    ".pcapng",
    ".pem",
    ".pfx",
    ".raw",
    ".sqlite",
    ".sqlite3",
    ".tfplan",
    ".tfstate",
    ".whl",
}
TEST_FIXTURE_SUFFIXES = {".db", ".pcap", ".pcapng", ".sqlite", ".sqlite3"}
SECRET_PATTERNS = {
    "private-key-header": re.compile(rb"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
    "aws-access-key": re.compile(rb"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
    "github-token": re.compile(rb"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_]{20,}"),
    "google-api-key": re.compile(rb"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{30,}"),
    "openai-key": re.compile(rb"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"),
    "slack-token": re.compile(rb"(?<![A-Za-z0-9])xox[baprs]-[0-9A-Za-z-]{10,}"),
    "stripe-live-key": re.compile(rb"(?<![A-Za-z0-9])sk_live_[0-9A-Za-z]{16,}"),
}


def git_output(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
    ).stdout


def repository_paths() -> list[Path]:
    candidates = git_output("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    return [Path(item.decode("utf-8")) for item in candidates.split(b"\0") if item]


def path_is_forbidden(path: Path) -> bool:
    name = path.name.casefold()
    if name == ".env.example":
        return False
    if name in FORBIDDEN_NAMES or name.startswith(".env."):
        return True
    suffix = path.suffix.casefold()
    if path.parts and path.parts[0] == "tests" and suffix in TEST_FIXTURE_SUFFIXES:
        return False
    return suffix in FORBIDDEN_SUFFIXES


def main() -> int:
    root = Path(git_output("rev-parse", "--show-toplevel").decode().strip()).resolve()
    failures: list[str] = []
    casefold_paths: dict[str, Path] = {}

    ignored_tracked = git_output("ls-files", "-ci", "--exclude-standard")
    if ignored_tracked:
        failures.append("tracked files also match .gitignore")

    for relative in repository_paths():
        path_key = relative.as_posix().casefold()
        previous = casefold_paths.setdefault(path_key, relative)
        if previous != relative:
            failures.append(f"case-insensitive path collision: {previous} and {relative}")

        if path_is_forbidden(relative):
            failures.append(f"forbidden public-repository file type: {relative}")

        absolute = root / relative
        if absolute.is_symlink():
            resolved = absolute.resolve(strict=False)
            if not resolved.is_relative_to(root):
                failures.append(f"symbolic link escapes repository: {relative}")
            continue
        if not absolute.is_file():
            continue

        size = absolute.stat().st_size
        if size > MAX_TRACKED_FILE_BYTES:
            failures.append(f"tracked file exceeds 5 MiB: {relative}")
            continue

        content = absolute.read_bytes()
        for detector, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                failures.append(f"{detector} signature in tracked file: {relative}")

    if failures:
        print("Repository hygiene check failed:", file=sys.stderr)
        for failure in sorted(set(failures)):
            print(f"- {failure}", file=sys.stderr)
        print("Secret values are intentionally omitted.", file=sys.stderr)
        return 1

    print("Repository hygiene check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
