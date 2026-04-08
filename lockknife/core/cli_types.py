from __future__ import annotations

import pathlib
import re
from typing import Any

import click

_RE_HEX = re.compile(r"^[a-fA-F0-9]+$")
_RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_RE_ANDROID_PKG = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")


class HashHexType(click.ParamType):
    name = "hashhex"

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> str:
        s = str(value).strip()
        if not _RE_HEX.match(s):
            self.fail("hash must be hex", param, ctx)
        if len(s) not in (32, 40, 64):
            self.fail("hash must be 32/40/64 hex chars (md5/sha1/sha256)", param, ctx)
        return s.lower()


class IPv4Type(click.ParamType):
    name = "ipv4"

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> str:
        s = str(value).strip()
        parts = s.split(".")
        if len(parts) != 4:
            self.fail("invalid IPv4 address", param, ctx)
        out: list[str] = []
        for p in parts:
            if not p.isdigit():
                self.fail("invalid IPv4 address", param, ctx)
            n = int(p)
            if n < 0 or n > 255:
                self.fail("invalid IPv4 address", param, ctx)
            out.append(str(n))
        return ".".join(out)


class DomainType(click.ParamType):
    name = "domain"

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> str:
        s = str(value).strip().lower()
        if not _RE_DOMAIN.match(s):
            self.fail("invalid domain", param, ctx)
        return s


class AndroidPackageType(click.ParamType):
    name = "androidpkg"

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> str:
        s = str(value).strip()
        if not _RE_ANDROID_PKG.match(s):
            self.fail("invalid Android package name", param, ctx)
        return s


class ReadableFileType(click.ParamType):
    name = "readablefile"

    def convert(
        self, value: Any, param: click.Parameter | None, ctx: click.Context | None
    ) -> pathlib.Path:
        p = pathlib.Path(str(value))
        if not p.exists() or not p.is_file():
            self.fail("file does not exist", param, ctx)
        try:
            p.open("rb").close()
        except Exception:
            self.fail("file is not readable", param, ctx)
        return p


HASH_HEX = HashHexType()
IPV4 = IPv4Type()
DOMAIN = DomainType()
ANDROID_PACKAGE = AndroidPackageType()
READABLE_FILE = ReadableFileType()
