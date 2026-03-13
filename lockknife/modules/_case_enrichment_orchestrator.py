from __future__ import annotations



import dataclasses

import csv

import pathlib

from typing import Any



from lockknife.core.case import case_output_path, load_case_manifest, register_case_artifact
from lockknife.core.exceptions import LockKnifeError

from lockknife.core.serialize import write_json

from lockknife.modules.ai.anomaly import anomaly_scores

from lockknife.modules.intelligence.cve import correlate_cves_for_apk_package

from lockknife.modules.intelligence.ioc import detect_iocs

from lockknife.modules._case_enrichment_helpers import (
    _artifact_path,
    _extract_package,
    _infer_numeric_feature_keys,
    _load_artifact_data,
    _selected_artifacts,
    _structured_rows,
    _unique_provider_status,
)

from lockknife.modules._case_enrichment_payloads import anomaly_payload, cve_payload, ioc_payload, password_payload

from lockknife.modules._case_enrichment_runs import _error_run_entry, _pcap_runs, _reputation_runs, _run_entry
from lockknife.modules._case_enrichment_summary import summarize_case_enrichment_runs



_NON_FATAL_ENRICHMENT_ERRORS: tuple[type[BaseException], ...] = (
    LockKnifeError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
    csv.Error,
)



def run_case_enrichment(
    *,
    case_dir: pathlib.Path,
    artifact_id: str | None = None,
    categories: list[str] | tuple[str, ...] | None = None,
    exclude_categories: list[str] | tuple[str, ...] | None = None,
    source_commands: list[str] | tuple[str, ...] | None = None,
    device_serials: list[str] | tuple[str, ...] | None = None,
    limit: int | None = 25,
    reputation_limit: int = 10,
    output: pathlib.Path | None = None,
) -> dict[str, Any]:
    manifest = load_case_manifest(case_dir)
    selected = _selected_artifacts(
        case_dir,
        artifact_id=artifact_id,
        categories=categories,
        exclude_categories=exclude_categories,
        source_commands=source_commands,
        device_serials=device_serials,
        limit=limit,
    )
    if output is None:
        output = case_output_path(case_dir, area="derived", filename=f"case_enrichment_{manifest.case_id}.json")

    runs: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    reputation_budget = max(int(reputation_limit), 0)

    for artifact in selected:
        path = _artifact_path(case_dir, str(artifact.get("path") or ""))
        if not path.exists():
            skipped.append({"artifact_id": artifact.get("artifact_id"), "path": str(path), "reason": "missing"})
            continue

        try:
            runs.extend(_pcap_runs(artifact, path))
        except _NON_FATAL_ENRICHMENT_ERRORS as exc:
            runs.append(_error_run_entry("network.case", artifact, str(exc), input_path=str(path)))

        try:
            raw = _load_artifact_data(path)
        except _NON_FATAL_ENRICHMENT_ERRORS as exc:
            skipped.append({"artifact_id": artifact.get("artifact_id"), "path": str(path), "reason": f"read-error: {exc}"})
            continue
        if raw is None:
            skipped.append({"artifact_id": artifact.get("artifact_id"), "path": str(path), "reason": "unsupported"})
            continue

        try:
            ioc_matches: list[dict[str, Any]] = []
            for match in detect_iocs(raw):
                if hasattr(match, "__dataclass_fields__"):
                    ioc_matches.append(dataclasses.asdict(match))
                elif isinstance(match, dict):
                    ioc_matches.append(match)
        except _NON_FATAL_ENRICHMENT_ERRORS as exc:
            runs.append(_error_run_entry("intelligence.ioc", artifact, str(exc), input_path=str(path)))
            ioc_matches = []
        if ioc_matches:
            runs.append(_run_entry("intelligence.ioc", artifact, ioc_payload(ioc_matches, input_path=path)))
            if reputation_budget > 0:
                for rep in _reputation_runs(artifact, path, ioc_matches, limit=reputation_budget):
                    runs.append(rep)
                    reputation_budget -= 1
                    if reputation_budget <= 0:
                        break

        package = _extract_package(raw)
        if package:
            try:
                runs.append(
                    _run_entry(
                        "intelligence.cve",
                        artifact,
                        cve_payload(package, correlate_cves_for_apk_package(package), input_paths=[str(path)]),
                    )
                )
            except _NON_FATAL_ENRICHMENT_ERRORS as exc:
                runs.append(_error_run_entry("intelligence.cve", artifact, str(exc), input_path=str(path)))

        rows = _structured_rows(raw)
        feature_keys = _infer_numeric_feature_keys(rows)
        if rows and feature_keys:
            try:
                scores = anomaly_scores(rows, feature_keys)
                runs.append(_run_entry("ai.anomaly_score", artifact, anomaly_payload(rows, feature_keys, scores, input_path=path)))
            except _NON_FATAL_ENRICHMENT_ERRORS as exc:
                runs.append(_error_run_entry("ai.anomaly_score", artifact, str(exc), input_path=str(path)))

    provider_status = _unique_provider_status(runs)
    run_summary = summarize_case_enrichment_runs(runs, skipped)
    summary = {
        "selected_artifact_count": len(selected),
        "workflow_run_count": len(runs),
        "provider_count": len(provider_status),
        "skipped_artifact_count": len(skipped),
        "reputation_budget_remaining": reputation_budget,
        "error_run_count": run_summary["error_count"],
    }
    payload: dict[str, Any] = {
        "case_dir": str(case_dir),
        "case_id": manifest.case_id,
        "title": manifest.title,
        "artifact_id": artifact_id if artifact_id else (selected[0].get("artifact_id") if len(selected) == 1 else None),
        "selected_artifacts": selected,
        "summary": summary,
        "runs": runs,
        "skipped_artifacts": skipped,
        "provider_status": provider_status,
        "source_attribution": provider_status,
        "run_summary": run_summary,
        "output": str(output),
        "category": "case-enrichment",
        "source_command": "case enrich",
        "input_paths": [str(_artifact_path(case_dir, str(item.get("path") or ""))) for item in selected],
        "parent_artifact_ids": [str(item.get("artifact_id")) for item in selected if str(item.get("artifact_id") or "").strip()],
    }
    write_json(output, payload)
    register_case_artifact(
        case_dir=case_dir,
        path=output,
        category="case-enrichment",
        source_command="case enrich",
        input_paths=payload["input_paths"],
        parent_artifact_ids=payload["parent_artifact_ids"],
        metadata=summary,
    )
    return payload
