from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlparse


def group_endpoints(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    routes: dict[str, Counter[str]] = defaultdict(Counter)
    methods: dict[str, Counter[str]] = defaultdict(Counter)
    for item in endpoints:
        endpoint = str(item.get("endpoint") or item.get("url") or "").strip()
        if not endpoint:
            continue
        host, route = _normalize_endpoint(endpoint)
        key = host or "unknown"
        bucket = grouped.setdefault(key, {"host": host, "count": 0, "sample_endpoints": []})
        bucket["count"] += 1
        if endpoint not in bucket["sample_endpoints"] and len(bucket["sample_endpoints"]) < 4:
            bucket["sample_endpoints"].append(endpoint)
        if route:
            routes[key][route] += 1
        method = str(item.get("method") or "").upper()
        if method:
            methods[key][method] += 1
    out: list[dict[str, Any]] = []
    for key, bucket in grouped.items():
        out.append(
            {
                **bucket,
                "top_routes": [
                    {"name": name, "count": count} for name, count in routes[key].most_common(5)
                ],
                "methods": [
                    {"name": name, "count": count} for name, count in methods[key].most_common(5)
                ],
            }
        )
    out.sort(key=lambda item: (-int(item.get("count") or 0), str(item.get("host") or "unknown")))
    return out[:12]


def _normalize_endpoint(endpoint: str) -> tuple[str | None, str | None]:
    if endpoint.startswith(("http://", "https://")):
        parsed = urlparse(endpoint)
        return parsed.hostname.lower() if parsed.hostname else None, _route(parsed.path)
    if "/" in endpoint:
        host, path = endpoint.split("/", 1)
        return host.lower() or None, _route("/" + path)
    return endpoint.lower() or None, None


def _route(path: str | None) -> str | None:
    if not path:
        return None
    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return "/"
    return "/" + "/".join(segments[:2])
