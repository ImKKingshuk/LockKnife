from __future__ import annotations

import re
from typing import Any, cast

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.secrets import load_secrets


class OtxError(LockKnifeError):
    pass


_RE_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_RE_DOMAIN = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def _require_otx() -> tuple[Any, Any]:
    try:
        from OTXv2 import IndicatorTypes, OTXv2
    except ImportError as e:
        raise OtxError("OTXv2 is required (install extras: lockknife[threat-intel])") from e
    return OTXv2, IndicatorTypes


def get_api_key() -> str:
    key = load_secrets().OTX_API_KEY
    if not key:
        raise OtxError("OTX_API_KEY is not set")
    return key


def classify_indicator(value: str) -> str:
    v = (value or "").strip()
    if _RE_SHA256.match(v):
        return "sha256"
    if _RE_IPV4.match(v):
        return "ipv4"
    if _RE_DOMAIN.match(v):
        return "domain"
    return "unknown"


def indicator_reputation(
    value: str, *, api_key: str | None = None, section: str = "general"
) -> dict[str, Any]:
    OTXv2, IndicatorTypes = _require_otx()
    key = api_key or get_api_key()
    otx = OTXv2(key)
    kind = classify_indicator(value)
    if kind == "ipv4":
        typ = IndicatorTypes.IPv4
    elif kind == "domain":
        typ = IndicatorTypes.DOMAIN
    elif kind == "sha256":
        typ = IndicatorTypes.FILE_HASH_SHA256
    else:
        raise OtxError("Unsupported indicator type")
    try:
        return cast(dict[str, Any], otx.get_indicator_details_full(typ, value))
    except Exception as e:
        raise OtxError("OTX query failed") from e
