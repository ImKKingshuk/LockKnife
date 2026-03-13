from lockknife.core.metrics import snapshot, track


def test_track_records_metrics() -> None:
    with track("op"):
        _ = sum([1, 2, 3])
    data = snapshot()
    assert "op" in data
    assert data["op"]["count"] >= 1
