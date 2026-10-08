"""Unit tests for Hotspot Gateway DNS Probing and hijacking detection."""

from __future__ import annotations

import socket
import struct
from unittest.mock import MagicMock, patch

from lockknife.modules.exploitation.hotspot.gateway import (
    GatewayResult,
    HotspotGateway,
)


def _make_dummy_dns_response(tx_id: int, resolved_ip: str) -> bytes:
    """Helper to synthesize a minimal DNS response containing one A record."""
    header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
    # Question: \x04test\x00 \x00\x01 \x00\x01
    question = b"\x04test\x00" + struct.pack("!HH", 1, 1)
    # Answer: pointer to name \xc0\x0c, TYPE A (1), CLASS IN (1), TTL 60, RDLENGTH 4, RDATA ip
    ip_bytes = socket.inet_aton(resolved_ip)
    answer = struct.pack("!HHIH", 1, 1, 60, 4)
    return header + question + b"\xc0\x0c" + answer + ip_bytes


def test_build_dns_query() -> None:
    """Test DNS query serialization."""
    query = HotspotGateway._build_dns_query("example.com", tx_id=0x1234)
    assert len(query) > 12
    tx_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", query[:12])
    assert tx_id == 0x1234
    assert flags == 0x0100
    assert qdcount == 1
    assert ancount == 0
    # Check question contains encoded domain labels
    assert b"\x07example\x03com\x00" in query


def test_parse_dns_response_valid() -> None:
    """Test parsing a valid DNS A record response."""
    resp = _make_dummy_dns_response(0x1337, "192.0.2.10")
    parsed = HotspotGateway._parse_dns_response(resp)
    assert parsed.get("tx_id") == 0x1337
    assert parsed.get("rcode") == 0
    assert parsed.get("answers") == ["192.0.2.10"]


def test_parse_dns_response_truncated() -> None:
    """Test handling of truncated response payload."""
    parsed = HotspotGateway._parse_dns_response(b"\x00\x01\x02")
    assert "error" in parsed


def test_exploit_dns_hijack_success() -> None:
    """Test DNS hijack detection when gateway returns rogue answer."""
    gateway = HotspotGateway()
    dummy_resp = _make_dummy_dns_response(0x1337, "192.0.2.1")

    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (dummy_resp, ("192.0.2.1", 53))

        result: GatewayResult = gateway._exploit_dns_hijack("192.0.2.1", timeout_s=1.0)
        assert result.success is True
        assert result.metadata.get("dns_hijack_detected") is True
        assert "probes" in result.metadata
        mock_sock.close.assert_called_once()


def test_exploit_dns_hijack_timeout() -> None:
    """Test DNS hijack probe when gateway resolver times out."""
    gateway = HotspotGateway()

    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = TimeoutError("Timed out")

        result: GatewayResult = gateway._exploit_dns_hijack("192.0.2.1", timeout_s=0.5)
        assert result.success is False
        assert "did not respond" in str(result.error)
