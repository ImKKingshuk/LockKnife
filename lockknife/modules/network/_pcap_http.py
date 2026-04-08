from __future__ import annotations

import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qs, urlparse

_REQUEST_LINE = re.compile(
    r"(?im)^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+([^\s]+)\s+HTTP/\d\.\d\s*$"
)
_RESPONSE_LINE = re.compile(r"(?i)HTTP/\d\.\d\s+(\d{3})\s+([^\r\n]+)")
_HOST_HEADER = re.compile(r"(?im)^host:\s*([^\s:]+)(?::\d+)?\s*$")
_FULL_URL = re.compile(r"\bhttps?://[a-zA-Z0-9._:-]+(?:/[^\s\"'<>)]*)?\b")
_CONTENT_TYPE = re.compile(r"(?im)^content-type:\s*([^\r\n;]+)")
_LOCATION = re.compile(r"(?im)^location:\s*([^\r\n]+)$")


def extract_http_requests(texts: list[str]) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for text in texts:
        for match in _REQUEST_LINE.finditer(text):
            method = str(match.group(1)).upper()
            path = str(match.group(2))
            window = text[match.start() : match.start() + 600]
            host_match = _HOST_HEADER.search(window)
            host = host_match.group(1).strip().lower() if host_match else None
            content_type = _CONTENT_TYPE.search(window)
            record = {
                "method": method,
                "path": path,
                "host": host,
                "url": _request_url(host, path),
                "content_type": content_type.group(1).strip() if content_type else None,
                "parameter_keys": _query_keys(_request_url(host, path)),
            }
            key = (method, host or "", path)
            if key in seen:
                continue
            seen.add(key)
            requests.append(record)

        for url_match in _FULL_URL.finditer(text):
            url = url_match.group(0)
            key = ("URL", "", url)
            if key in seen:
                continue
            seen.add(key)
            requests.append(
                {
                    "method": "URL",
                    "path": url,
                    "host": _host_from_url(url),
                    "url": url,
                    "content_type": None,
                    "parameter_keys": _query_keys(url),
                }
            )
    return requests[:200]


def extract_http_responses(texts: list[str]) -> list[dict[str, Any]]:
    responses: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for text in texts:
        for match in _RESPONSE_LINE.finditer(text):
            status_code = str(match.group(1))
            reason = str(match.group(2)).strip()
            window = text[match.start() : match.start() + 600]
            content_type = _CONTENT_TYPE.search(window)
            location = _LOCATION.search(window)
            key = (status_code, reason)
            if key in seen:
                continue
            seen.add(key)
            responses.append(
                {
                    "status_code": status_code,
                    "reason": reason,
                    "content_type": content_type.group(1).strip() if content_type else None,
                    "location": location.group(1).strip() if location else None,
                }
            )
    return responses[:120]


def summarize_http_requests(
    requests: list[dict[str, Any]], responses: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    method_counts = Counter(str(item.get("method") or "unknown") for item in requests)
    hosts = [
        str(item.get("host") or "").strip()
        for item in requests
        if str(item.get("host") or "").strip()
    ]
    unique_hosts = sorted(set(hosts))
    status_counts = Counter(
        str(item.get("status_code") or "")
        for item in (responses or [])
        if str(item.get("status_code") or "")
    )
    return {
        "request_count": len(requests),
        "response_count": len(responses or []),
        "host_count": len(unique_hosts),
        "top_methods": [
            {"name": name, "count": count} for name, count in method_counts.most_common(6)
        ],
        "top_status_codes": [
            {"name": name, "count": count} for name, count in status_counts.most_common(6)
        ],
        "hosts": unique_hosts[:25],
        "requests": requests[:25],
        "responses": (responses or [])[:25],
    }


def _request_url(host: str | None, path: str) -> str:
    if path.startswith(("http://", "https://")):
        return path
    if host:
        prefix = "" if path.startswith("/") else "/"
        return f"https://{host}{prefix}{path}"
    return path


def _host_from_url(url: str) -> str | None:
    if "://" not in url:
        return None
    remainder = url.split("://", 1)[1]
    return remainder.split("/", 1)[0].split(":", 1)[0].lower() or None


def _query_keys(url: str) -> list[str]:
    try:
        parsed = urlparse(url)
    except Exception:
        return []
    return sorted(parse_qs(parsed.query).keys())[:20]
