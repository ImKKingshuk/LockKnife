from __future__ import annotations

import re
from collections import Counter
from typing import Any

_TLS_SERVER_NAME = re.compile(r"(?i)(?:server_name|sni|hostname)[:=\s]+([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})")
_TLS_ALPN = re.compile(r"(?i)(?:alpn|application_layer_protocol)[:=\s]+([a-zA-Z0-9._/-]+)")


def extract_tls_metadata(texts: list[str]) -> dict[str, Any]:
    server_names: list[str] = []
    alpns: list[str] = []
    seen_hosts: set[str] = set()
    seen_alpn: set[str] = set()
    for text in texts:
        for match in _TLS_SERVER_NAME.finditer(text):
            host = match.group(1).strip().strip(".").lower()
            if host and host not in seen_hosts:
                seen_hosts.add(host)
                server_names.append(host)
        for match in _TLS_ALPN.finditer(text):
            alpn = match.group(1).strip().lower()
            if alpn and alpn not in seen_alpn:
                seen_alpn.add(alpn)
                alpns.append(alpn)
    return summarize_tls_metadata(server_names, alpns)


def summarize_tls_metadata(server_names: list[str], alpns: list[str]) -> dict[str, Any]:
    host_counts = Counter(server_names)
    alpn_counts = Counter(alpns)
    return {
        "server_name_count": len(server_names),
        "server_names": server_names[:25],
        "top_server_names": [{"name": name, "count": count} for name, count in host_counts.most_common(8)],
        "alpn": [{"name": name, "count": count} for name, count in alpn_counts.most_common(6)],
    }