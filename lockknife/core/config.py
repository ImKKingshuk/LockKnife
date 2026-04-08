from __future__ import annotations

import os
import pathlib
import tomllib
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field

from lockknife.core.exceptions import ConfigError


class LockKnifeConfig(BaseModel):
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="console")
    adb_path: str | None = Field(default=None)


@dataclass(frozen=True)
class LoadedConfig:
    config: LockKnifeConfig
    path: pathlib.Path | None


def _candidate_config_paths() -> list[pathlib.Path]:
    home = pathlib.Path.home()
    return [
        pathlib.Path.cwd() / "lockknife.toml",
        home / ".config" / "lockknife" / "lockknife.toml",
        home / ".lockknife.toml",
        pathlib.Path("/etc/lockknife.toml"),
    ]


def _candidate_legacy_paths() -> list[pathlib.Path]:
    home = pathlib.Path.home()
    return [
        pathlib.Path.cwd() / "lockknife.conf",
        home / ".config" / "lockknife" / "lockknife.conf",
        home / ".lockknife.conf",
        pathlib.Path("/etc/lockknife.conf"),
    ]


def _parse_legacy_kv(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        key = k.strip().lower()
        val = v.strip().strip("'").strip('"')
        out[key] = val
    return out


def load_config() -> LoadedConfig:
    override = os.environ.get("LOCKKNIFE_CONFIG")
    if override:
        path = pathlib.Path(override).expanduser()
        if not path.exists():
            raise ConfigError(f"LOCKKNIFE_CONFIG points to missing file: {path}")
        return LoadedConfig(config=_load_from_path(path), path=path)

    for path in _candidate_config_paths():
        if path.exists():
            return LoadedConfig(config=_load_from_path(path), path=path)

    for path in _candidate_legacy_paths():
        if path.exists():
            data = _parse_legacy_kv(path.read_text(encoding="utf-8"))
            mapped = {
                "log_level": data.get("log_level") or data.get("loglevel"),
                "log_format": data.get("log_format") or data.get("logformat"),
                "adb_path": data.get("adb_path") or data.get("adb"),
            }
            cleaned = {k: v for k, v in mapped.items() if v is not None}
            return LoadedConfig(config=LockKnifeConfig.model_validate(cleaned), path=path)

    return LoadedConfig(config=LockKnifeConfig(), path=None)


def _load_from_path(path: pathlib.Path) -> LockKnifeConfig:
    if path.suffix == ".toml":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "lockknife" in data and isinstance(data["lockknife"], dict):
            data = data["lockknife"]
        if not isinstance(data, dict):
            raise ConfigError(f"Invalid TOML config structure in {path}")
        return LockKnifeConfig.model_validate(data)

    data = _parse_legacy_kv(path.read_text(encoding="utf-8"))
    return LockKnifeConfig.model_validate(data)
