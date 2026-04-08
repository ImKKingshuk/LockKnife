from __future__ import annotations

import pathlib
from typing import Any

from lockknife.core.exceptions import LockKnifeError
from lockknife.modules._case_enrichment_common import _PCAP_SUFFIXES, _looks_like_sha256, _source
from lockknife.modules._case_enrichment_payloads import (
    api_discovery_payload,
    network_summary_payload,
    otx_payload,
    virustotal_payload,
)
from lockknife.modules.intelligence.otx import indicator_reputation
from lockknife.modules.intelligence.virustotal import file_report
from lockknife.modules.network.api_discovery import extract_api_endpoints_from_pcap, summarize_pcap

_NON_FATAL_ENRICHMENT_ERRORS: tuple[type[BaseException], ...] = (
    LockKnifeError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)


def _run_entry(workflow: str, artifact: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "workflow": workflow,
        "artifact_id": artifact.get("artifact_id"),
        "artifact_path": artifact.get("path"),
        "artifact_category": artifact.get("category"),
        "payload": payload,
    }


def _error_run_entry(
    workflow: str, artifact: dict[str, Any], error: str, *, input_path: str
) -> dict[str, Any]:
    return _run_entry(
        workflow,
        artifact,
        {
            "summary": {"input_path": input_path, "error": error},
            "error": error,
            "source_attribution": [
                _source(
                    "lockknife-case-enrichment",
                    mode="local",
                    description="Case enrichment orchestration recorded a workflow failure.",
                )
            ],
        },
    )


def _pcap_runs(artifact: dict[str, Any], path: pathlib.Path) -> list[dict[str, Any]]:
    if path.suffix.lower() not in _PCAP_SUFFIXES and "network-capture" not in str(
        artifact.get("category") or ""
    ):
        return []
    return [
        _run_entry(
            "network.summarize",
            artifact,
            network_summary_payload(summarize_pcap(path), input_path=path),
        ),
        _run_entry(
            "network.api_discovery",
            artifact,
            api_discovery_payload(extract_api_endpoints_from_pcap(path), input_path=path),
        ),
    ]


def _reputation_runs(
    artifact: dict[str, Any],
    path: pathlib.Path,
    matches: list[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for match in matches:
        if len(runs) >= limit:
            break
        indicator = str(match.get("ioc") or "").strip()
        kind = str(match.get("kind") or "").strip().lower()
        if not indicator or (kind, indicator) in seen:
            continue
        seen.add((kind, indicator))
        if kind in {"domain", "ipv4", "url", "sha256"}:
            try:
                runs.append(
                    _run_entry(
                        "intelligence.otx",
                        artifact,
                        otx_payload(
                            indicator, indicator_reputation(indicator), input_paths=[str(path)]
                        ),
                    )
                )
            except _NON_FATAL_ENRICHMENT_ERRORS as exc:
                runs.append(
                    _error_run_entry("intelligence.otx", artifact, str(exc), input_path=str(path))
                )
        if kind == "sha256" and len(runs) < limit and _looks_like_sha256(indicator):
            try:
                runs.append(
                    _run_entry(
                        "intelligence.virustotal",
                        artifact,
                        virustotal_payload(
                            indicator, file_report(indicator), input_paths=[str(path)]
                        ),
                    )
                )
            except _NON_FATAL_ENRICHMENT_ERRORS as exc:
                runs.append(
                    _error_run_entry(
                        "intelligence.virustotal", artifact, str(exc), input_path=str(path)
                    )
                )
    return runs[:limit]
