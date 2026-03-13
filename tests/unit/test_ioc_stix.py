from lockknife.modules.intelligence.ioc import parse_stix_bundle_for_iocs


def test_parse_stix_bundle_for_iocs_domain_and_ip() -> None:
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'example.com'] AND [ipv4-addr:value = '1.2.3.4']",
            }
        ],
    }
    out = parse_stix_bundle_for_iocs(bundle, location="x")
    kinds = {m.kind for m in out}
    assert "domain" in kinds
    assert "ipv4" in kinds
