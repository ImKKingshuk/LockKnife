import types

import pytest


def test_android_cve_risk_score_uses_cvss(monkeypatch) -> None:
    from lockknife.modules.intelligence import cve as cve_mod

    monkeypatch.setattr(
        cve_mod,
        "query_osv",
        lambda q: {"vulns": [{"severity": [{"score": "9.1"}]}]},
    )
    out = cve_mod.android_cve_risk_score(34)
    assert out["risk"] == "critical"
    assert out["osv_vuln_count"] == 1
    assert out["support_status"] == "supported"


def test_query_osv_wraps_non_dict(monkeypatch) -> None:
    from lockknife.modules.intelligence import cve as cve_mod

    monkeypatch.setattr(cve_mod, "http_post_json", lambda *args, **kwargs: ["x"])
    out = cve_mod.query_osv("q")
    assert out["raw"] == ["x"]


def test_correlate_cves_for_apk_package(monkeypatch) -> None:
    from lockknife.modules.intelligence import cve as cve_mod

    monkeypatch.setattr(cve_mod, "query_osv", lambda q: {"vulns": [], "query": q})
    out = cve_mod.correlate_cves_for_apk_package("com.example")
    assert out["query"] == "com.example"


def test_android_cve_risk_score_sdk_fallback_paths(monkeypatch) -> None:
    from lockknife.modules.intelligence import cve as cve_mod

    monkeypatch.setattr(cve_mod, "query_osv", lambda q: {"vulns": []})
    assert cve_mod.android_cve_risk_score(23)["risk"] == "critical"

    def boom(_q: str):
        raise RuntimeError("x")

    monkeypatch.setattr(cve_mod, "query_osv", boom)
    assert cve_mod.android_cve_risk_score(0)["risk"] == "unknown"


def test_kernel_version_mapping() -> None:
    from lockknife.modules.intelligence import cve as cve_mod

    out = cve_mod.correlate_cves_for_kernel_version("5.10.168-android12-9")
    assert out["kernel_branch"] == "5.10"
    assert out["mapping_confidence"] == "high"
    assert isinstance(out["known_cves"], list)


def test_ioc_parsing_and_stix(monkeypatch) -> None:
    from lockknife.modules.intelligence import ioc as ioc_mod

    hits = ioc_mod.detect_iocs({"indicator_hash": "a" * 64, "remote_ip": "1.2.3.4", "domain": "example.com"})
    kinds = {h.kind for h in hits}
    assert "sha256" in kinds
    assert "ipv4" in kinds
    assert "domain" in kinds
    assert all(h.confidence > 0 for h in hits)

    pat_hits = ioc_mod.parse_stix_pattern("[domain-name:value = 'example.com' AND ipv4-addr:value = '8.8.8.8']", location="x")
    assert pat_hits[0].ioc == "example.com"
    assert any(hit.kind == "composite_and" for hit in pat_hits)

    bundle = {"objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '8.8.8.8']"}]}
    b_hits = ioc_mod.parse_stix_bundle_for_iocs(bundle, location="b")
    assert b_hits[0].ioc == "8.8.8.8"

    monkeypatch.setattr(ioc_mod, "http_get", lambda url, **kwargs: b'{"objects":[]}')
    assert ioc_mod.load_stix_indicators_from_url("https://x") == []


def test_ioc_helpers_and_composites(monkeypatch) -> None:
    from lockknife.modules.intelligence import ioc as ioc_mod

    fragments = ioc_mod._iter_text_fragments({"outer": [None, {"value": "https://example.test 8.8.8.8"}]}, location="root")
    assert fragments == [("root.outer[1].value", "https://example.test 8.8.8.8")]

    match = ioc_mod.IocMatch(ioc="8.8.8.8", kind="ipv4", location="remote_ip", confidence=0.8)
    assert ioc_mod._condition_matches(match, {"kind": "ipv4", "pattern": r"8\.8", "min_confidence": 0.7}) is True
    assert ioc_mod._condition_matches(match, {"ioc": "1.1.1.1"}) is False
    assert ioc_mod._is_valid_ipv4("999.1.1.1") is False
    assert ioc_mod._stix_boolean_operator("[a OR b]") == "OR"
    assert ioc_mod._stix_boolean_operator("[a]") is None

    matches = [
        ioc_mod.IocMatch(ioc="evil.example", kind="domain", location="host", confidence=0.7),
        ioc_mod.IocMatch(ioc="8.8.8.8", kind="ipv4", location="remote_ip", confidence=0.8),
    ]
    rules = [
        {"name": "combo-and", "operator": "and", "confidence_boost": 0.1, "conditions": [{"kind": "domain"}, {"kind": "ipv4"}]},
        {"name": "combo-or", "operator": "or", "conditions": [{"ioc": "evil.example"}, {"ioc": "missing"}]},
        {"name": "ignored", "conditions": []},
        "bad",
    ]
    out = ioc_mod.evaluate_composite_iocs(matches, rules)
    assert {item.kind for item in out} == {"composite_and", "composite_or"}
    assert any(item.ioc == "combo-and" and "8.8.8.8" in item.evidence for item in out)


def test_ioc_stix_and_taxii_fallback_paths(monkeypatch) -> None:
    from lockknife.modules.intelligence import ioc as ioc_mod

    monkeypatch.setattr(ioc_mod, "http_get", lambda _url, **_kwargs: b"raw indicator 1.2.3.4 https://fallback.example")
    fallback_hits = ioc_mod.load_stix_indicators_from_url("https://fallback.test")
    assert {hit.kind for hit in fallback_hits} >= {"ipv4", "url", "domain"}

    assert ioc_mod.parse_stix_bundle_for_iocs({"objects": [None, {"type": "malware"}]}, location="bundle") == []

    bundle = {
        "objects": [
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'example.com']",
                "name": "Indicator https://named.example",
                "description": "Contact 9.9.9.9",
            }
        ]
    }
    bundle_hits = ioc_mod.parse_stix_bundle_for_iocs(bundle, location="bundle")
    kinds = {hit.kind for hit in bundle_hits}
    assert {"domain", "url", "ipv4"} <= kinds

    headers = ioc_mod._taxii_headers(token="tok", username="u", password="p")
    assert headers["Authorization"].startswith("Basic ")

    monkeypatch.setattr(ioc_mod, "http_get_json", lambda *_a, **_k: {"collections": []})
    assert ioc_mod.load_taxii_indicators("https://taxii.example/api") == []

    monkeypatch.setattr(ioc_mod, "http_get_json", lambda *_a, **_k: {"collections": ["invalid"]})
    assert ioc_mod.load_taxii_indicators("https://taxii.example/api") == []

    requests: dict[str, object] = {}

    def _get_json(url, headers, **_kwargs):
        requests["collections_url"] = url
        requests["headers"] = headers
        return {"collections": [{"id": "col-1"}]}

    def _get(url, headers, **_kwargs):
        requests["objects_url"] = url
        requests["object_headers"] = headers
        return b"url https://taxii.example/ioc 5.5.5.5"

    monkeypatch.setattr(ioc_mod, "http_get_json", _get_json)
    monkeypatch.setattr(ioc_mod, "http_get", _get)
    taxii_hits = ioc_mod.load_taxii_indicators(
        "https://taxii.example/api",
        added_after="2024-01-01T00:00:00Z",
        token="secret",
        limit=7,
    )
    assert any(hit.kind == "url" for hit in taxii_hits)
    assert any(hit.kind == "ipv4" for hit in taxii_hits)
    assert "limit=7" in str(requests["objects_url"])
    assert "added_after=2024-01-01T00%3A00%3A00Z" in str(requests["objects_url"])
    assert requests["headers"]["Authorization"] == "Bearer secret"


def test_virustotal_requires_api_key(monkeypatch) -> None:
    from lockknife.modules.intelligence import virustotal as vt_mod

    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(Exception):
        vt_mod.get_api_key()


def test_virustotal_file_report_uses_client(monkeypatch) -> None:
    from lockknife.modules.intelligence import virustotal as vt_mod

    submitted: dict[str, str] = {}

    class _Client:
        def __init__(self, key: str) -> None:
            self._key = key

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get_object(self, path: str):
            return types.SimpleNamespace(to_dict=lambda: {"path": path, "attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 7}}})

        def scan_url(self, url: str):
            submitted["url"] = url
            return types.SimpleNamespace(to_dict=lambda: {"data": {"id": "analysis-1"}})

    monkeypatch.setenv("VT_API_KEY", "k")
    monkeypatch.setitem(__import__("sys").modules, "vt", types.SimpleNamespace(Client=_Client, url_id=lambda url: f"id-{url}"))
    out = vt_mod.file_report("a" * 64)
    assert out["path"].endswith("/files/" + ("a" * 64))
    assert out["summary"]["detection_ratio"] == 0.3

    url_out = vt_mod.url_report("https://example.com")
    assert "/urls/id-https://example.com" in url_out["path"]

    domain_out = vt_mod.domain_report("example.com")
    assert domain_out["path"].endswith("/domains/example.com")

    ip_out = vt_mod.ip_report("8.8.8.8")
    assert ip_out["path"].endswith("/ip_addresses/8.8.8.8")

    submit_out = vt_mod.submit_url_for_analysis("https://submit.example")
    assert submitted["url"] == "https://submit.example"
    assert submit_out["submission_id"] == "analysis-1"
