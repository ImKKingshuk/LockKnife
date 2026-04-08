from lockknife.core.feature_matrix import FEATURE_STATUSES, filter_features, iter_features


def test_feature_statuses_are_known() -> None:
    rows = iter_features()
    assert rows
    assert all(row.status in FEATURE_STATUSES for row in rows)


def test_filter_features_by_status() -> None:
    rows = filter_features(status="dependency-gated")
    assert rows
    assert all(row.status == "dependency-gated" for row in rows)


def test_filter_features_by_category() -> None:
    rows = filter_features(category="apk")
    assert rows
    assert all(row.category == "apk" for row in rows)
