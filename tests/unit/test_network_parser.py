import pathlib

from lockknife.modules.network.parser import analyze_pcap, parse_ipv4_header


def test_parse_ipv4_header() -> None:
    pkt = bytes.fromhex("450000140000000040060000c000020108080808")
    out = parse_ipv4_header(pkt)
    assert out["src"] == "192.0.2.1"


def test_analyze_pcap_extracts_structured_text_protocols(tmp_path: pathlib.Path) -> None:
    pcap = tmp_path / "sample.pcap"
    pcap.write_text(
        "GET /v1/users/42?limit=10 HTTP/1.1\r\n"
        "Host: api.example.com\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        "dns query auth.example.com answer 192.0.2.4\n"
        "server_name secure.example.com\n",
        encoding="utf-8",
    )

    out = analyze_pcap(pcap)

    assert out["http"]["request_count"] >= 1
    assert out["http"]["response_count"] >= 1
    assert out["dns"]["answer_count"] >= 1
    assert "secure.example.com" in out["tls"]["server_names"]
