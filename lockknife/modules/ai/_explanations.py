from __future__ import annotations

import statistics
from collections import Counter
from typing import Any

from lockknife.modules._case_enrichment_common import _float_or_none


def anomaly_explainability(rows: list[dict[str, Any]], results: list[dict[str, Any]], feature_keys: list[str]) -> dict[str, Any]:
    baselines: dict[str, tuple[float, float]] = {}
    for key in feature_keys:
        numeric_values = [_float_or_none(row.get(key)) for row in rows]
        values = [value for value in numeric_values if value is not None]
        if not values:
            continue
        baselines[key] = (statistics.fmean(values), statistics.pstdev(values) or 0.0)
    sorted_results = sorted(results, key=lambda entry: float(entry.get("anomaly_score") or 0.0), reverse=True)
    top_rows: list[dict[str, Any]] = []
    for item in sorted_results[:3]:
        row_obj = item.get("row")
        row = row_obj if isinstance(row_obj, dict) else {}
        contributors: list[dict[str, Any]] = []
        for key in feature_keys:
            value = _float_or_none(row.get(key))
            if value is None or key not in baselines:
                continue
            mean, stdev = baselines[key]
            zscore = 0.0 if stdev == 0.0 else abs(value - mean) / stdev
            contributors.append({"feature": key, "value": value, "mean": round(mean, 4), "zscore": round(zscore, 3)})
        contributors.sort(key=lambda entry: float(entry.get("zscore") or 0.0), reverse=True)
        top_rows.append(
            {
                "anomaly_score": item.get("anomaly_score"),
                "top_contributors": contributors[:3],
                "row_preview": {key: row.get(key) for key in feature_keys[:4]},
            }
        )
    scores = [float(item.get("anomaly_score") or 0.0) for item in results]
    return {
        "feature_keys": feature_keys,
        "top_rows": top_rows,
        "baseline_count": len(baselines),
        "score_distribution": {
            "min": min(scores) if scores else 0.0,
            "max": max(scores) if scores else 0.0,
            "mean": round(statistics.fmean(scores), 4) if scores else 0.0,
        },
        "confidence_notes": [
            "Anomaly scores are relative to the supplied cohort, not absolute proof of maliciousness.",
            "Review the top contributing features before escalating any outlier as a finding.",
        ],
    }


def password_explainability(source_words: list[str], predictions: list[str]) -> dict[str, Any]:
    lengths = [len(word) for word in source_words if word]
    prefixes = Counter(word[:2] for word in source_words if len(word) >= 2)
    suffixes = Counter(word[-2:] for word in source_words if len(word) >= 2)
    predicted_lengths = Counter(len(word) for word in predictions if word)
    return {
        "source_length_range": [min(lengths), max(lengths)] if lengths else [],
        "top_prefixes": [{"token": token, "count": count} for token, count in prefixes.most_common(3)],
        "top_suffixes": [{"token": token, "count": count} for token, count in suffixes.most_common(3)],
        "predicted_length_distribution": [
            {"length": length, "count": count}
            for length, count in sorted(predicted_lengths.items(), key=lambda item: (item[0], item[1]))[:6]
        ],
        "sample_predictions": predictions[:5],
        "confidence_notes": [
            "Generated candidates reflect patterns in the training corpus and may repeat its biases.",
            "Treat predictions as heuristic guesses until validated against controlled cracking workflows.",
        ],
    }