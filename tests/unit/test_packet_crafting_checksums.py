"""Unit tests for RFC 791 / RFC 768 packet crafting checksum calculations."""

from __future__ import annotations

import struct

from lockknife.modules.exploitation.zeroclick.payload import (
    PayloadGenerator,
    PayloadType,
)


def test_calculate_checksum_rfc_compliance() -> None:
    """Test 16-bit one's complement Internet Checksum computation."""
    # Arbitrary test data
    data = b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c"
    chk = PayloadGenerator._calculate_checksum(data)
    assert 0 <= chk <= 0xFFFF

    # When placing the computed checksum in the 0x0000 slot:
    with_chk = data[:10] + struct.pack("!H", chk) + data[12:]
    # Recalculating checksum over header containing valid checksum yields 0
    verification = PayloadGenerator._calculate_checksum(with_chk)
    assert verification == 0


def test_ip_header_valid_checksum() -> None:
    """Test generated IP header contains an authentic verified checksum."""
    generator = PayloadGenerator()
    header = generator._create_ip_header("192.0.2.1", payload_len=40, protocol="tcp")
    assert len(header) == 20
    # Verification over entire header must be 0
    verification = generator._calculate_checksum(header)
    assert verification == 0


def test_transport_header_tcp_checksum() -> None:
    """Test TCP transport header checksum calculation."""
    generator = PayloadGenerator()
    payload = b"TEST_PAYLOAD"
    tcp_hdr = generator._create_transport_header(80, "tcp", payload=payload, target_ip="192.0.2.1")
    assert len(tcp_hdr) == 20
    # Verify non-zero checksum was placed
    _, _, _, _, _, _, _, chk, _ = struct.unpack("!HHIIBBHHH", tcp_hdr)
    assert chk != 0


def test_transport_header_udp_checksum() -> None:
    """Test UDP transport header checksum calculation."""
    generator = PayloadGenerator()
    payload = b"DNS_PROBE_BYTES"
    udp_hdr = generator._create_transport_header(53, "udp", payload=payload, target_ip="192.0.2.1")
    assert len(udp_hdr) == 8
    _, _, length, chk = struct.unpack("!HHHH", udp_hdr)
    assert length == 8 + len(payload)
    assert chk != 0


def test_generate_network_packet_payload() -> None:
    """Test end-to-end network packet generation."""
    generator = PayloadGenerator()
    packet_payload = generator.generate_network_packet_payload(
        cve_id="CVE-2025-48593",
        target_ip="192.0.2.55",
        target_port=443,
        protocol="tcp",
    )
    assert packet_payload.payload_type == PayloadType.NETWORK_PACKET
    assert len(packet_payload.data) > 40  # IP (20) + TCP (20) + trigger
