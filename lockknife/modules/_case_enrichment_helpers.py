from __future__ import annotations



import csv

import json

import pathlib

from collections import Counter

from typing import Any



from lockknife.core.case import case_artifact_details, query_case_artifacts

from lockknife.modules.ai._explanations import anomaly_explainability, password_explainability

from lockknife.modules._case_enrichment_common import _MAX_TEXT_BYTES, _TEXT_SUFFIXES, _float_or_none



def _selected_artifacts(
    case_dir: pathlib.Path,
    *,
    artifact_id: str | None,
    categories: list[str] | tuple[str, ...] | None,
    exclude_categories: list[str] | tuple[str, ...] | None,
    source_commands: list[str] | tuple[str, ...] | None,
    device_serials: list[str] | tuple[str, ...] | None,
    limit: int | None,
) -> list[dict[str, Any]]:
    if artifact_id:
        detail = case_artifact_details(case_dir, artifact_id=artifact_id)
        return [detail["artifact"]] if detail else []
    return list(
        (query_case_artifacts(
            case_dir,
            categories=categories,
            exclude_categories=exclude_categories,
            source_commands=source_commands,
            device_serials=device_serials,
            limit=limit,
        ).get("artifacts") or [])
    )

def _artifact_path(case_dir: pathlib.Path, stored_path: str) -> pathlib.Path:
    path = pathlib.Path(stored_path)
    return path if path.is_absolute() else case_dir / stored_path

def _load_artifact_data(path: pathlib.Path) -> Any | None:
    suffix = path.suffix.lower()
    if suffix not in _TEXT_SUFFIXES or path.stat().st_size > _MAX_TEXT_BYTES:
        return None
    if suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    if suffix == ".csv":
        with path.open("r", encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))
    return path.read_text(encoding="utf-8", errors="ignore")

def _extract_package(data: Any) -> str | None:
    if isinstance(data, dict):
        package = data.get("package")
        if isinstance(package, str) and package.strip():
            return package.strip()
        manifest = data.get("manifest")
        if isinstance(manifest, dict):
            package = manifest.get("package")
            if isinstance(package, str) and package.strip():
                return package.strip()
    return None

def _structured_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list) and all(isinstance(item, dict) for item in data):
        return [dict(item) for item in data]
    return []

def _infer_numeric_feature_keys(rows: list[dict[str, Any]]) -> list[str]:
    if len(rows) < 3:
        return []
    counts: Counter[str] = Counter()
    for row in rows:
        for key, value in row.items():
            if _float_or_none(value) is not None:
                counts[str(key)] += 1
    threshold = max(2, min(len(rows), 3))
    return [key for key, count in counts.items() if count >= threshold][:6]

def _anomaly_explainability(
    rows: list[dict[str, Any]], results: list[dict[str, Any]], feature_keys: list[str]
) -> dict[str, Any]:
    return anomaly_explainability(rows, results, feature_keys)

def _password_explainability(source_words: list[str], predictions: list[str]) -> dict[str, Any]:
    return password_explainability(source_words, predictions)

def _unique_provider_status(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for run in runs:
        payload = run.get("payload") if isinstance(run, dict) else None
        sources = payload.get("source_attribution") if isinstance(payload, dict) else None
        if not isinstance(sources, list):
            continue
        for source in sources:
            if not isinstance(source, dict):
                continue
            provider = str(source.get("provider") or "").strip()
            if not provider or provider in seen:
                continue
            seen.add(provider)
            out.append(source)
    return out
