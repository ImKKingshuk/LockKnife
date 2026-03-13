import pytest

from lockknife.modules.forensics.correlation import correlate_artifacts_json_blobs


def test_correlate_artifacts_json_blobs() -> None:
    pytest.importorskip("lockknife.lockknife_core")
    out = correlate_artifacts_json_blobs(['[{"number":"+1"}]', '[{"ssid":"Home"}]'])
    assert "+1" in str(out)
    assert "edges" in out
