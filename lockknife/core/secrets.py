from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Secrets(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env",), env_file_encoding="utf-8", extra="ignore")

    VT_API_KEY: str | None = None
    OTX_API_KEY: str | None = None


def load_secrets() -> Secrets:
    return Secrets()
