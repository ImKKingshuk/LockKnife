from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter
from importlib import import_module
from typing import Any, cast

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.logging import get_logger
from lockknife.modules.network._pcap_dns import extract_dns_records, summarize_dns_records
from lockknife.modules.network._pcap_http import extract_http_requests, extract_http_responses, summarize_http_requests
from lockknife.modules.network._pcap_tls import extract_tls_metadata


class NetworkParseError(LockKnifeError):
    pass


log = get_logger()


def parse_ipv4_header(packet_bytes: bytes) -> dict[str, Any]:
    try:
        import lockknife.lockknife_core as lockknife_core
    except ImportError as e:
        raise NetworkParseError("lockknife_core extension is not available") from e
    out = lockknife_core.parse_ipv4_header_json(packet_bytes)
    return cast(dict[str, Any], json.loads(out))


def analyze_pcap(path: pathlib.Path) -> dict[str, Any]:
    raw = path.read_bytes()
    texts = [raw.decode("utf-8", errors="ignore")]
    protocols: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    connection_edges: dict[tuple[str, str, str, int | None, int | None], dict[str, Any]] = {}
    total_packets: int | None = None
    dns_records: list[dict[str, Any]] = []
    try:
        scapy = sys.modules.get("scapy.all") or import_module("scapy.all")

        DNS = getattr(scapy, "DNS", None)
        IP = getattr(scapy, "IP", None)
        IPv6 = getattr(scapy, "IPv6", None)
        Raw = getattr(scapy, "Raw", None)
        TCP = getattr(scapy, "TCP", None)
        UDP = getattr(scapy, "UDP", None)
        rdpcap = scapy.rdpcap

        packets = rdpcap(str(path))
        total_packets = int(len(packets))
        for pkt in packets:
            payload_length = _packet_size(pkt, Raw=Raw)
            src, dst = _packet_hosts(pkt, IP=IP, IPv6=IPv6)
            if _has_layer(pkt, TCP):
                protocols["tcp"] += 1
                sport = int(getattr(pkt[TCP], "sport", 0) or 0)
                dport = int(getattr(pkt[TCP], "dport", 0) or 0)
                ports[str(dport)] += 1
                _accumulate_edge(connection_edges, src, dst, "tcp", sport, dport, payload_length)
            elif _has_layer(pkt, UDP):
                protocols["udp"] += 1
                sport = int(getattr(pkt[UDP], "sport", 0) or 0)
                dport = int(getattr(pkt[UDP], "dport", 0) or 0)
                ports[str(dport)] += 1
                _accumulate_edge(connection_edges, src, dst, "udp", sport, dport, payload_length)
            elif src or dst:
                protocols["ip"] += 1
                _accumulate_edge(connection_edges, src, dst, "ip", None, None, payload_length)
            if _has_layer(pkt, DNS):
                dns_records.extend(_dns_records_from_packet(pkt[DNS]))
            if _has_layer(pkt, Raw):
                try:
                    text = bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
                except (AttributeError, TypeError, ValueError):
                    text = ""
                if text.strip():
                    texts.append(text)
    except ModuleNotFoundError:
        pass
    except (AttributeError, OSError, TypeError, ValueError):
        log.warning("pcap_deep_parse_failed", exc_info=True, pcap=str(path))

    text_dns_records = extract_dns_records(texts)
    seen_dns = {(str(item.get("query") or ""), str(item.get("answer") or "")) for item in dns_records}
    for record in text_dns_records:
        key = (str(record.get("query") or ""), str(record.get("answer") or ""))
        if key in seen_dns:
            continue
        seen_dns.add(key)
        dns_records.append(record)
    http_requests = extract_http_requests(texts)
    http_responses = extract_http_responses(texts)
    tls = extract_tls_metadata(texts)
    hosts = sorted(
        {
            edge["src"] for edge in connection_edges.values() if edge.get("src")
        }
        | {
            edge["dst"] for edge in connection_edges.values() if edge.get("dst")
        }
        | {str(item.get("host") or "") for item in http_requests if str(item.get("host") or "")}
        | set(str(item) for item in (tls.get("server_names") or []) if str(item))
    )
    return {
        "pcap": str(path),
        "texts": texts[:50],
        "total_packets": total_packets,
        "protocols": dict(sorted(protocols.items())),
        "top_ports": [{"name": name, "count": count} for name, count in ports.most_common(8)],
        "dns": summarize_dns_records(dns_records),
        "http": summarize_http_requests(http_requests, http_responses),
        "tls": tls,
        "hosts": hosts[:50],
        "connections": _summarize_connections(list(connection_edges.values())),
    }


def _packet_hosts(pkt: Any, *, IP: Any, IPv6: Any) -> tuple[str | None, str | None]:
    if _has_layer(pkt, IP):
        return str(getattr(pkt[IP], "src", None) or "") or None, str(getattr(pkt[IP], "dst", None) or "") or None
    if _has_layer(pkt, IPv6):
        return str(getattr(pkt[IPv6], "src", None) or "") or None, str(getattr(pkt[IPv6], "dst", None) or "") or None
    return None, None


def _has_layer(pkt: Any, layer: Any) -> bool:
    if layer is None:
        return False
    try:
        return bool(pkt.haslayer(layer))
    except (AttributeError, TypeError, ValueError):
        return False


def _packet_size(pkt: Any, *, Raw: Any) -> int:
    try:
        return len(bytes(pkt))
    except (TypeError, ValueError):
        if _has_layer(pkt, Raw):
            payload = getattr(pkt[Raw], "load", b"")
            if isinstance(payload, str):
                return len(payload.encode("utf-8", errors="ignore"))
            if isinstance(payload, (bytes, bytearray)):
                return len(payload)
        return 0


def _accumulate_edge(edges: dict[tuple[str, str, str, int | None, int | None], dict[str, Any]], src: str | None, dst: str | None, protocol: str, sport: int | None, dport: int | None, size_bytes: int) -> None:
    key = (src or "unknown", dst or "unknown", protocol, sport, dport)
    bucket = edges.setdefault(
        key,
        {"src": src, "dst": dst, "protocol": protocol, "source_port": sport, "dest_port": dport, "packet_count": 0, "byte_count": 0},
    )
    bucket["packet_count"] += 1
    bucket["byte_count"] += int(size_bytes)


def _dns_records_from_packet(layer: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    question = getattr(layer, "qd", None)
    if question is not None:
        qname = getattr(question, "qname", b"")
        query = qname.decode("utf-8", errors="ignore").strip(".") if isinstance(qname, (bytes, bytearray)) else str(qname).strip(".")
        if query:
            out.append({"query": query.lower(), "answer": None, "source": "scapy"})
    answer = getattr(layer, "an", None)
    if answer is not None:
        rrname = getattr(answer, "rrname", b"")
        rdata = getattr(answer, "rdata", None)
        query = rrname.decode("utf-8", errors="ignore").strip(".") if isinstance(rrname, (bytes, bytearray)) else str(rrname).strip(".")
        resolved = str(rdata).strip() if rdata is not None else None
        if query:
            out.append({"query": query.lower(), "answer": resolved or None, "source": "scapy"})
    return out


def _summarize_connections(edges: list[dict[str, Any]]) -> dict[str, Any]:
    destination_counts = Counter(str(item.get("dst") or "") for item in edges if str(item.get("dst") or ""))
    nodes = sorted({str(item.get("src") or "") for item in edges if str(item.get("src") or "")} | {str(item.get("dst") or "") for item in edges if str(item.get("dst") or "")})
    ranked = sorted(edges, key=lambda item: (-int(item.get("packet_count") or 0), -int(item.get("byte_count") or 0), str(item.get("dst") or "")))
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes[:25],
        "top_destinations": [{"name": name, "count": count} for name, count in destination_counts.most_common(8)],
        "edges": ranked[:25],
    }
