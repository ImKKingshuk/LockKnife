from lockknife.modules.intelligence.otx import classify_indicator


def test_classify_indicator() -> None:
    assert classify_indicator("1.2.3.4") == "ipv4"
    assert classify_indicator("example.com") == "domain"
    assert classify_indicator("a" * 64) == "sha256"
