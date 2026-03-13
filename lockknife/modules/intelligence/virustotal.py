from __future__ import annotations

import ipaddress
from urllib.parse import quote_plus

from typing import Any
from typing import cast

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.secrets import load_secrets


class VirusTotalError(LockKnifeError):
    pass


def _require_vt() -> Any:
    try:
        import vt
    except ImportError as e:
        raise VirusTotalError("vt-py is required (install extras: lockknife[threat-intel])") from e
    return vt


def get_api_key() -> str:
    key = load_secrets().VT_API_KEY
    if not key:
        raise VirusTotalError("VT_API_KEY is not set")
    return key


def file_report(file_hash: str, api_key: str | None = None) -> dict[str, Any]:
    return lookup_indicator_report(file_hash, indicator_type="file", api_key=api_key)


def url_report(url: str, api_key: str | None = None) -> dict[str, Any]:
    return lookup_indicator_report(url, indicator_type="url", api_key=api_key)


def domain_report(domain: str, api_key: str | None = None) -> dict[str, Any]:
    return lookup_indicator_report(domain, indicator_type="domain", api_key=api_key)


def ip_report(address: str, api_key: str | None = None) -> dict[str, Any]:
    return lookup_indicator_report(address, indicator_type="ip", api_key=api_key)


def lookup_indicator_report(indicator: str, *, indicator_type: str, api_key: str | None = None) -> dict[str, Any]:
    vt = _require_vt()
    key = api_key or get_api_key()
    path = _vt_path(indicator, indicator_type=indicator_type, vt=vt)
    with vt.Client(key) as client:
        obj = _get_object(client, path)
        return _augment_report(indicator, indicator_type=indicator_type, payload=_to_dict(obj))


def submit_url_for_analysis(url: str, api_key: str | None = None) -> dict[str, Any]:
    vt = _require_vt()
    key = api_key or get_api_key()
    with vt.Client(key) as client:
        if hasattr(client, "scan_url"):
            response = client.scan_url(url)
        else:
            response = client.post_object("/urls", data={"url": url})
        payload = _to_dict(response)
        payload.setdefault("submitted", True)
        payload.setdefault("target", url)
        payload.setdefault("indicator_type", "url")
        payload.setdefault("submission_id", str((payload.get("data") or {}).get("id") or payload.get("id") or ""))
        return payload


def _vt_path(indicator: str, *, indicator_type: str, vt: Any) -> str:
    kind = indicator_type.strip().lower()
    if kind == "file":
        return f"/files/{indicator}"
    if kind == "url":
        if hasattr(vt, "url_id"):
            return f"/urls/{vt.url_id(indicator)}"
        return f"/urls/{quote_plus(indicator)}"
    if kind == "domain":
        return f"/domains/{indicator}"
    if kind == "ip":
        return f"/ip_addresses/{ipaddress.ip_address(indicator)}"
    raise VirusTotalError(f"Unsupported VirusTotal indicator type: {indicator_type}")


def _get_object(client: Any, path: str) -> Any:
    try:
        return client.get_object(path)
    except TypeError:
        return client.get_object("{}", path)


def _to_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, dict):
        return cast(dict[str, Any], obj)
    if hasattr(obj, "to_dict"):
        return cast(dict[str, Any], obj.to_dict())
    return {"raw": obj}


def _augment_report(indicator: str, *, indicator_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    attrs = payload.get("attributes") if isinstance(payload, dict) else None
    stats = attrs.get("last_analysis_stats") if isinstance(attrs, dict) else None
    if isinstance(stats, dict):
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        timeout = int(stats.get("timeout") or 0)
        total = malicious + suspicious + harmless + undetected + timeout
    else:
        malicious = suspicious = harmless = undetected = timeout = total = 0
    detection_hits = malicious + suspicious
    detection_ratio = round(detection_hits / total, 4) if total else 0.0
    payload.setdefault("subject", indicator)
    payload.setdefault("indicator_type", indicator_type)
    payload.setdefault(
        "summary",
        {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "timeout_count": timeout,
            "engine_total": total,
            "detection_hits": detection_hits,
            "detection_ratio": detection_ratio,
            "detection_ratio_text": f"{detection_hits}/{total}" if total else "0/0",
            "confidence_score": min(100, int(round(detection_ratio * 100)) + (25 if detection_hits else 5)),
        },
    )
    return payload
