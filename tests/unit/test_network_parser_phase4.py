import pathlib
import sys
import types

import pytest

from lockknife.modules.network.parser import (
    NetworkParseError,
    _has_layer,
    _packet_size,
    analyze_pcap,
    parse_ipv4_header,
)


def test_parse_ipv4_header_raises_when_extension_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def _raising_import(name: str, *args: object, **kwargs: object):
        if name == "lockknife.lockknife_core":
            raise ImportError("missing extension")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _raising_import)
    with pytest.raises(NetworkParseError, match="extension is not available"):
        parse_ipv4_header(b"\x45\x00")


def test_analyze_pcap_uses_fake_scapy_packets(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pcap = tmp_path / "sample.pcap"
    pcap.write_text("GET /status HTTP/1.1\r\nHost: api.example.com\r\n\r\n", encoding="utf-8")

    class IP:
        pass

    class TCP:
        pass

    class Raw:
        pass

    class DNS:
        pass

    class _Layer:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

    class _Packet:
        def __init__(self) -> None:
            self.layers = {
                IP: _Layer(src="192.0.2.1", dst="192.0.2.2"),
                TCP: _Layer(sport=1234, dport=443),
                Raw: _Layer(load=b"GET /status HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
                DNS: _Layer(
                    qd=_Layer(qname=b"api.example.com."),
                    an=_Layer(rrname=b"api.example.com.", rdata="192.0.2.4"),
                ),
            }

        def haslayer(self, layer: object) -> bool:
            return layer in self.layers

        def __getitem__(self, layer: object) -> object:
            return self.layers[layer]

        def __bytes__(self) -> bytes:
            return b"packet-bytes"

    fake_scapy = types.SimpleNamespace(
        IP=IP, IPv6=None, TCP=TCP, UDP=None, Raw=Raw, DNS=DNS, rdpcap=lambda _path: [_Packet()]
    )
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy)

    out = analyze_pcap(pcap)

    assert out["total_packets"] == 1
    assert out["protocols"]["tcp"] == 1
    assert out["dns"]["answer_count"] >= 1
    assert any(edge["dest_port"] == 443 for edge in out["connections"]["edges"])


def test_packet_helpers_handle_error_fallbacks() -> None:
    class Raw:
        pass

    class _Packet:
        def haslayer(self, _layer: object) -> bool:
            raise TypeError("bad layer lookup")

        def __bytes__(self) -> bytes:
            raise TypeError("bad bytes")

        def __getitem__(self, _layer: object) -> object:
            return types.SimpleNamespace(load="hello")

    pkt = _Packet()
    assert _has_layer(pkt, Raw) is False
    assert _packet_size(pkt, Raw=Raw) == 0
