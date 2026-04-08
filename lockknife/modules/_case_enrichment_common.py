from __future__ import annotations

import pathlib
from collections import Counter
from typing import Any

from lockknife.core.secrets import load_secrets

_PCAP_SUFFIXES = {".pcap", ".pcapng"}

_TEXT_SUFFIXES = {".json", ".csv", ".txt", ".log", ".xml", ".md", ".yaml", ".yml"}

_MAX_TEXT_BYTES = 2_000_000


def _base_payload(
    *,
    case_dir: pathlib.Path | None = None,
    output: pathlib.Path | None = None,
    input_paths: list[str] | None = None,
    category: str | None = None,
    source_command: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if case_dir is not None:
        payload["case_dir"] = str(case_dir)
    if output is not None:
        payload["output"] = str(output)
    if input_paths:
        payload["input_paths"] = [str(path) for path in input_paths]
    if category:
        payload["category"] = category
    if source_command:
        payload["source_command"] = source_command
    return payload


def _source(
    provider: str,
    *,
    mode: str,
    description: str,
    credential_required: bool = False,
    credential_configured: bool | None = None,
    credential_source: str | None = None,
    cache_mode: str = "none",
    cache_ttl_s: int | None = None,
    rate_limit_hint: str | None = None,
) -> dict[str, Any]:
    payload = {
        "provider": provider,
        "mode": mode,
        "description": description,
        "credentials": {
            "required": credential_required,
            "configured": credential_configured,
            "source": credential_source,
        },
        "cache": {"mode": cache_mode, "ttl_s": cache_ttl_s},
    }
    if rate_limit_hint:
        payload["rate_limit_hint"] = rate_limit_hint
    return payload


def _secret_status(name: str) -> tuple[bool, str | None]:
    secrets = load_secrets()
    value = getattr(secrets, name, None)
    configured = bool(value and str(value).strip())
    return configured, f"env:{name}" if configured else None


def _hash_prefix(value: str) -> str:
    trimmed = (value or "").strip()
    return trimmed[:16] if trimmed else "value"


def _looks_like_sha256(value: str) -> bool:
    text = (value or "").strip().lower()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _safe_package(value: str) -> str:
    return (
        "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value).strip("._")
        or "package"
    )


def _summarize_matches(matches: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(str(match.get("kind") or "unknown") for match in matches)
    unique_iocs = {
        str(match.get("ioc") or "").strip()
        for match in matches
        if str(match.get("ioc") or "").strip()
    }
    confidences = [
        float(match.get("confidence") or 0.0)
        for match in matches
        if isinstance(match.get("confidence"), (int, float))
    ]
    return {
        "match_count": len(matches),
        "unique_ioc_count": len(unique_iocs),
        "composite_count": sum(
            1 for match in matches if str(match.get("kind") or "").startswith("composite_")
        ),
        "max_confidence": round(max(confidences), 3) if confidences else 0.0,
        "avg_confidence": round(sum(confidences) / len(confidences), 3) if confidences else 0.0,
        "by_kind": [{"name": name, "count": count} for name, count in sorted(counts.items())],
    }


def _float_or_none(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None
