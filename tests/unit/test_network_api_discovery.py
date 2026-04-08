import pathlib

from lockknife.modules.network.api_discovery import discover_api_endpoints_from_text, extract_api_endpoints_from_pcap, summarize_pcap


def test_discover_api_endpoints_from_text_urls() -> None:
    text = "GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\nhttps://a.example/x"
    out = discover_api_endpoints_from_text(text, source="x")
    eps = {e.endpoint for e in out}
    assert "https://a.example/x" in eps
    assert "api.example.com/v1/users" in eps


def test_pcap_summary_includes_http_dns_tls_hints(tmp_path: pathlib.Path) -> None:
    pcap = tmp_path / "sample.pcap"
    pcap.write_text(
        "GET /v1/users/42?limit=10 HTTP/1.1\r\n"
        "Host: api.example.com\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        "dns query auth.example.com answer 192.0.2.4\n"
        "server_name secure.example.com\n",
        encoding="utf-8",
    )

    discovery = extract_api_endpoints_from_pcap(pcap)
    summary = summarize_pcap(pcap)

    assert "api.example.com" in discovery["hosts"]
    assert discovery["http"]["request_count"] >= 1
    assert discovery["http"]["response_count"] >= 1
    assert "auth.example.com" in discovery["dns"]["domains"]
    assert discovery["parameter_keys"] == ["limit"]
    assert discovery["summary"]["fingerprint_count"] >= 1
    assert "secure.example.com" in discovery["tls"]["server_names"]
    assert summary["summary"]["http_request_count"] >= 1
    assert summary["summary"]["http_response_count"] >= 1
