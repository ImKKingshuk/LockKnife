from __future__ import annotations

import dataclasses
import pathlib
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from lockknife.core.logging import get_logger
from lockknife.modules.network._endpoint_grouping import group_endpoints
from lockknife.modules.network.parser import analyze_pcap


@dataclasses.dataclass(frozen=True)
class ApiEndpoint:
    endpoint: str
    kind: str
    source: str


_RE_URL = re.compile(r"\bhttps?://[a-zA-Z0-9._:-]+(?:/[^\s\"'<>)]*)?\b")
_RE_HOST = re.compile(r"(?im)^\s*host:\s*([^\s:]+)(?::\d+)?\s*$")
_RE_PATH = re.compile(
    r"(?im)^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+([^\s]+)\s+HTTP/\d\.\d\s*$"
)

log = get_logger()


def discover_api_endpoints_from_text(text: str, *, source: str) -> list[ApiEndpoint]:
    out: dict[str, ApiEndpoint] = {}
    for m in _RE_URL.finditer(text):
        url = m.group(0)
        out[url] = ApiEndpoint(endpoint=url, kind="url", source=source)
    hosts = [m.group(1) for m in _RE_HOST.finditer(text)]
    paths = [m.group(2) for m in _RE_PATH.finditer(text)]
    if hosts and paths:
        for h in hosts[:50]:
            for p in paths[:200]:
                if p.startswith("http://") or p.startswith("https://"):
                    out[p] = ApiEndpoint(endpoint=p, kind="url", source=source)
                else:
                    out[f"{h}{p}"] = ApiEndpoint(
                        endpoint=f"{h}{p}", kind="host+path", source=source
                    )
    return list(out.values())


def extract_api_endpoints_from_pcap(path: pathlib.Path) -> dict[str, Any]:
    analysis = analyze_pcap(path)
    texts = [str(item) for item in analysis.get("texts") or []]
    endpoints = discover_api_endpoints_from_text("\n".join(texts[:20]), source=str(path))
    endpoint_rows = [dataclasses.asdict(e) for e in endpoints]
    http_requests = list((analysis.get("http") or {}).get("requests") or [])
    seen_fingerprints = {
        str(item.get("fingerprint") or "")
        for item in endpoint_rows
        if str(item.get("fingerprint") or "")
    }
    for request in http_requests:
        url = str(request.get("url") or "").strip()
        if not url:
            continue
        pattern = _normalize_url_pattern(url)
        fingerprint = _endpoint_fingerprint(
            str(request.get("method") or "GET"), str(request.get("host") or ""), pattern
        )
        if fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)
        endpoint_rows.append(
            {
                "endpoint": url,
                "kind": "http-request",
                "source": str(path),
                "method": request.get("method"),
                "host": request.get("host"),
                "pattern": pattern,
                "parameter_keys": list(request.get("parameter_keys") or []),
                "fingerprint": fingerprint,
            }
        )
    for row in endpoint_rows:
        endpoint = str(row.get("endpoint") or "").strip()
        if endpoint and not row.get("pattern"):
            row["pattern"] = _normalize_url_pattern(endpoint)
        if endpoint and not row.get("host"):
            row["host"] = _host_for_endpoint(endpoint)
        if endpoint and not row.get("parameter_keys"):
            row["parameter_keys"] = _parameter_keys(endpoint)
        if not row.get("fingerprint"):
            row["fingerprint"] = _endpoint_fingerprint(
                str(row.get("method") or "GET"),
                str(row.get("host") or ""),
                str(row.get("pattern") or endpoint),
            )
    hosts = sorted({str(item) for item in (analysis.get("hosts") or []) if str(item)})
    grouped = group_endpoints(endpoint_rows)
    parameter_keys = sorted(
        {key for row in endpoint_rows for key in list(row.get("parameter_keys") or [])}
    )
    fingerprints = sorted(
        {
            str(row.get("fingerprint") or "")
            for row in endpoint_rows
            if str(row.get("fingerprint") or "")
        }
    )
    summary = {
        "input_path": str(path),
        "endpoint_count": len(endpoint_rows),
        "host_count": len(hosts),
        "group_count": len(grouped),
        "http_request_count": len(http_requests),
        "fingerprint_count": len(fingerprints),
        "parameter_key_count": len(parameter_keys),
        "dns_query_count": int((analysis.get("dns") or {}).get("query_count") or 0),
        "tls_server_name_count": int((analysis.get("tls") or {}).get("server_name_count") or 0),
        "connection_edge_count": int((analysis.get("connections") or {}).get("edge_count") or 0),
    }
    return {
        "pcap": str(path),
        "endpoints": endpoint_rows,
        "hosts": hosts,
        "endpoint_groups": grouped,
        "http": analysis.get("http") or {},
        "dns": analysis.get("dns") or {},
        "tls": analysis.get("tls") or {},
        "connections": analysis.get("connections") or {},
        "parameter_keys": parameter_keys,
        "fingerprints": fingerprints[:50],
        "summary": summary,
        "review_notes": _review_notes(grouped, hosts, http_requests, analysis),
    }


def summarize_pcap(path: pathlib.Path) -> dict[str, Any]:
    discovery = extract_api_endpoints_from_pcap(path)
    analysis = analyze_pcap(path)
    summary: dict[str, Any] = {
        "pcap": str(path),
        "total_packets": analysis.get("total_packets"),
        "protocols": analysis.get("protocols") or {},
        "endpoints": discovery.get("endpoints") or [],
        "hosts": discovery.get("hosts") or [],
        "endpoint_groups": discovery.get("endpoint_groups") or [],
        "http": discovery.get("http") or {},
        "dns": discovery.get("dns") or {},
        "tls": discovery.get("tls") or {},
        "connections": discovery.get("connections") or {},
        "top_ports": analysis.get("top_ports") or [],
        "parameter_keys": discovery.get("parameter_keys") or [],
        "fingerprints": discovery.get("fingerprints") or [],
        "review_notes": discovery.get("review_notes") or [],
    }
    summary["summary"] = {
        "input_path": str(path),
        "host_count": len(summary.get("hosts") or []),
        "protocol_count": len(summary.get("protocols") or {}),
        "endpoint_count": len(summary.get("endpoints") or []),
        "http_request_count": int((summary.get("http") or {}).get("request_count") or 0),
        "http_response_count": int((summary.get("http") or {}).get("response_count") or 0),
        "dns_query_count": int((summary.get("dns") or {}).get("query_count") or 0),
        "tls_server_name_count": int((summary.get("tls") or {}).get("server_name_count") or 0),
        "connection_edge_count": int((summary.get("connections") or {}).get("edge_count") or 0),
        "parameter_key_count": len(summary.get("parameter_keys") or []),
    }
    return summary


def _review_notes(
    grouped: list[dict[str, Any]],
    hosts: list[str],
    http_requests: list[dict[str, Any]],
    analysis: dict[str, Any],
) -> list[str]:
    notes: list[str] = []
    if grouped:
        top = grouped[0]
        notes.append(
            f"Top endpoint cluster: {top.get('host') or 'unknown'} with {top.get('count') or 0} endpoint observations."
        )
    if any(str(item.get("url") or "").startswith("http://") for item in http_requests):
        notes.append("Cleartext HTTP requests were observed in the capture preview.")
    if int((analysis.get("tls") or {}).get("server_name_count") or 0):
        notes.append(
            "TLS SNI metadata is available; compare hosts and endpoints for certificate-bound API surfaces."
        )
    if int((analysis.get("connections") or {}).get("edge_count") or 0) >= 5:
        notes.append(
            "Connection graph shows multiple flows; review top destinations and port reuse before scoping trust boundaries."
        )
    if len(hosts) >= 5:
        notes.append(
            "Multiple destination hosts were observed; review host grouping before drawing API conclusions."
        )
    if not notes:
        notes.append(
            "Capture summary is best-effort and should be validated against packet-level evidence when decisions matter."
        )
    return notes[:4]


def _normalize_url_pattern(endpoint: str) -> str:
    if endpoint.startswith(("http://", "https://")):
        parsed = urlparse(endpoint)
        path = parsed.path or "/"
    else:
        path = endpoint.split("/", 1)[1] if "/" in endpoint else endpoint
        path = "/" + path.lstrip("/")
    normalized_segments = []
    for segment in [part for part in path.split("/") if part]:
        if re.fullmatch(r"[0-9]+", segment):
            normalized_segments.append("{int}")
        elif re.fullmatch(r"[0-9a-fA-F]{8,}", segment) or re.fullmatch(
            r"[0-9a-fA-F-]{16,}", segment
        ):
            normalized_segments.append("{id}")
        else:
            normalized_segments.append(segment)
    return "/" + "/".join(normalized_segments) if normalized_segments else "/"


def _parameter_keys(endpoint: str) -> list[str]:
    if not endpoint.startswith(("http://", "https://")):
        endpoint = f"https://{endpoint}"
    try:
        parsed = urlparse(endpoint)
    except Exception:
        return []
    return sorted(parse_qs(parsed.query).keys())[:20]


def _host_for_endpoint(endpoint: str) -> str | None:
    if endpoint.startswith(("http://", "https://")):
        parsed = urlparse(endpoint)
        return parsed.hostname.lower() if parsed.hostname else None
    return endpoint.split("/", 1)[0].lower() if "/" in endpoint else endpoint.lower()


def _endpoint_fingerprint(method: str, host: str, pattern: str) -> str:
    return f"{method.upper()} {host or 'unknown'} {pattern}"
