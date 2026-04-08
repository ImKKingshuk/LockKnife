from __future__ import annotations


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def safe_passkey_filename(remote_path: str) -> str:
    cleaned = remote_path.strip("/").replace("/", "_")
    return cleaned or "passkey_artifact"
