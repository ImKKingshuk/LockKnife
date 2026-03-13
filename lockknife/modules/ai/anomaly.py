from __future__ import annotations

from typing import Any


class AiError(RuntimeError):
    pass


def _require_sklearn() -> tuple[Any, Any, Any]:
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.neighbors import LocalOutlierFactor
    except ImportError as e:
        raise AiError("scikit-learn and numpy are required (install extras: lockknife[ml])") from e
    return np, IsolationForest, LocalOutlierFactor


def anomaly_scores(rows: list[dict[str, Any]], feature_keys: list[str]) -> list[dict[str, Any]]:
    if not rows:
        return []
    np, IsolationForest, LocalOutlierFactor = _require_sklearn()
    resolved_keys = feature_keys or _infer_numeric_feature_keys(rows)
    if not resolved_keys:
        return []
    X = [[float(r.get(k) or 0.0) for k in resolved_keys] for r in rows]
    Xn = np.array(X, dtype=float)
    isolation_forest = IsolationForest(random_state=0, n_estimators=300, contamination="auto")
    isolation_forest.fit(Xn)
    iforest_raw = _to_list(-isolation_forest.score_samples(Xn))
    try:
        neighbors = max(2, min(20, len(rows) - 1))
        if neighbors >= 2:
            local_outlier_factor = LocalOutlierFactor(n_neighbors=neighbors, contamination="auto")
            local_outlier_factor.fit(Xn)
            lof_raw = _to_list(-local_outlier_factor.negative_outlier_factor_)
        else:
            lof_raw = list(iforest_raw)
    except Exception:
        lof_raw = list(iforest_raw)
    iforest_scores = _normalize_scores(iforest_raw)
    lof_scores = _normalize_scores(lof_raw)
    feature_stats = _feature_stats(rows, resolved_keys)
    combined_scores = [round((iforest_scores[idx] + lof_scores[idx]) / 2.0, 6) for idx in range(len(rows))]
    ranking = {index: rank + 1 for rank, index in enumerate(sorted(range(len(combined_scores)), key=lambda idx: combined_scores[idx], reverse=True))}
    out: list[dict[str, Any]] = []
    for idx, row in enumerate(rows):
        out.append(
            {
                "row": row,
                "row_index": idx,
                "anomaly_score": combined_scores[idx],
                "rank": ranking[idx],
                "feature_keys": resolved_keys,
                "models": {
                    "isolation_forest": iforest_scores[idx],
                    "local_outlier_factor": lof_scores[idx],
                },
                "explanation": {
                    "top_features": _top_feature_explanations(row, resolved_keys, feature_stats),
                },
            }
        )
    return out


def _infer_numeric_feature_keys(rows: list[dict[str, Any]]) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key, value in row.items():
            if isinstance(value, (int, float)) and key not in seen:
                seen.add(str(key))
                keys.append(str(key))
    return keys


def _normalize_scores(values: list[float]) -> list[float]:
    if not values:
        return []
    minimum = min(values)
    maximum = max(values)
    if maximum <= minimum:
        return [0.0 for _ in values]
    return [round((value - minimum) / (maximum - minimum), 6) for value in values]


def _feature_stats(rows: list[dict[str, Any]], feature_keys: list[str]) -> dict[str, dict[str, float]]:
    stats: dict[str, dict[str, float]] = {}
    for key in feature_keys:
        values = [float(row.get(key) or 0.0) for row in rows]
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        stats[key] = {"mean": mean, "std": variance ** 0.5}
    return stats


def _top_feature_explanations(row: dict[str, Any], feature_keys: list[str], feature_stats: dict[str, dict[str, float]]) -> list[dict[str, float | str]]:
    explanations: list[dict[str, float | str]] = []
    for key in feature_keys:
        value = float(row.get(key) or 0.0)
        stats = feature_stats.get(key) or {"mean": 0.0, "std": 0.0}
        std = float(stats.get("std") or 0.0)
        z_score = (value - float(stats.get("mean") or 0.0)) / std if std > 0 else 0.0
        explanations.append(
            {
                "feature": key,
                "value": round(value, 6),
                "mean": round(float(stats.get("mean") or 0.0), 6),
                "z_score": round(z_score, 6),
                "contribution": round(abs(z_score), 6),
            }
        )
    return sorted(explanations, key=lambda item: float(item.get("contribution") or 0.0), reverse=True)[:5]


def _to_list(values: Any) -> list[float]:
    if hasattr(values, "tolist"):
        return [float(item) for item in values.tolist()]
    return [float(item) for item in values]
