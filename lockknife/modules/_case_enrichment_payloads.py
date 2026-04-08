from __future__ import annotations

import pathlib
from typing import Any, cast

from lockknife.modules._case_enrichment_common import (
    _base_payload,
    _secret_status,
    _summarize_matches,
)
from lockknife.modules._case_enrichment_helpers import (
    _anomaly_explainability,
    _password_explainability,
)
from lockknife.modules.intelligence._attribution import attributed_source
from lockknife.modules.intelligence._confidence import coverage_summary


def network_summary_payload(
    summary: dict[str, Any],
    *,
    input_path: pathlib.Path,
    case_dir: pathlib.Path | None = None,
    output: pathlib.Path | None = None,
) -> dict[str, Any]:
    payload = dict(summary)
    payload.update(
        _base_payload(
            case_dir=case_dir,
            output=output,
            input_paths=[str(input_path)],
            category="network-analysis",
            source_command="network analyze",
        )
    )
    payload["summary"] = {
        "input_path": str(input_path),
        "host_count": len(payload.get("hosts") or []),
        "protocol_count": len(payload.get("protocols") or []),
        "endpoint_count": len(payload.get("endpoints") or []),
        "http_request_count": int((payload.get("http") or {}).get("request_count") or 0),
        "http_response_count": int((payload.get("http") or {}).get("response_count") or 0),
        "dns_query_count": int((payload.get("dns") or {}).get("query_count") or 0),
        "tls_server_name_count": int((payload.get("tls") or {}).get("server_name_count") or 0),
        "connection_edge_count": int((payload.get("connections") or {}).get("edge_count") or 0),
        "parameter_key_count": len(payload.get("parameter_keys") or []),
    }
    payload["source_attribution"] = [
        attributed_source(
            "lockknife-local-pcap-summary",
            mode="local",
            description="Offline PCAP summarization from the supplied capture file.",
            subject=str(input_path),
            evidence_count=len(payload.get("endpoints") or []),
        )
    ]
    payload["coverage"] = coverage_summary(
        str(input_path),
        evidence_count=len(payload.get("endpoints") or []),
        confidence="moderate",
        providers=["lockknife-local-pcap-summary"],
    )
    return payload


def api_discovery_payload(
    discovery: dict[str, Any],
    *,
    input_path: pathlib.Path,
    case_dir: pathlib.Path | None = None,
    output: pathlib.Path | None = None,
) -> dict[str, Any]:
    payload = dict(discovery)
    payload.update(
        _base_payload(
            case_dir=case_dir,
            output=output,
            input_paths=[str(input_path)],
            category="network-api-discovery",
            source_command="network api-discovery",
        )
    )
    payload["summary"] = {
        "input_path": str(input_path),
        "endpoint_count": len(payload.get("endpoints") or []),
        "host_count": len(payload.get("hosts") or []),
        "group_count": len(payload.get("endpoint_groups") or []),
        "parameter_key_count": len(payload.get("parameter_keys") or []),
        "fingerprint_count": len(payload.get("fingerprints") or []),
    }
    payload["source_attribution"] = [
        attributed_source(
            "lockknife-local-api-discovery",
            mode="local",
            description="Offline API endpoint extraction from the supplied capture file.",
            subject=str(input_path),
            evidence_count=len(payload.get("endpoints") or []),
        )
    ]
    payload["coverage"] = coverage_summary(
        str(input_path),
        evidence_count=len(payload.get("endpoints") or []),
        confidence="moderate",
        providers=["lockknife-local-api-discovery"],
    )
    return payload


def ioc_payload(
    matches: list[dict[str, Any]],
    *,
    input_path: pathlib.Path,
    case_dir: pathlib.Path | None = None,
    output: pathlib.Path | None = None,
) -> dict[str, Any]:
    payload = {
        "matches": matches,
        "summary": {"input_path": str(input_path), **_summarize_matches(matches)},
        "source_attribution": [
            attributed_source(
                "lockknife-local-ioc-detection",
                mode="local",
                description="Pattern-based IOC extraction over the supplied local artifact.",
                subject=str(input_path),
                evidence_count=len(matches),
            )
        ],
    }
    payload["coverage"] = coverage_summary(
        str(input_path),
        evidence_count=len(matches),
        confidence="high"
        if float(cast(dict[str, Any], payload["summary"]).get("max_confidence") or 0.0) >= 0.85
        else ("moderate" if matches else "limited"),
        providers=["lockknife-local-ioc-detection"],
    )
    payload.update(
        _base_payload(
            case_dir=case_dir,
            output=output,
            input_paths=[str(input_path)],
            category="intel-ioc",
            source_command="intel ioc",
        )
    )
    return payload


def cve_payload(
    package: str,
    report: dict[str, Any],
    *,
    case_dir: pathlib.Path | None = None,
    output: pathlib.Path | None = None,
    input_paths: list[str] | None = None,
) -> dict[str, Any]:
    vulns = report.get("vulns") if isinstance(report, dict) else None
    vuln_list = (
        [item for item in vulns if isinstance(item, dict)] if isinstance(vulns, list) else []
    )
    payload = {
        "package": package,
        "report": report,
        "summary": {
            "package": package,
            "vulnerability_count": len(vuln_list),
            "critical_or_high_count": sum(
                1
                for item in vuln_list
                if str(item.get("severity") or "").lower() in {"critical", "high"}
            ),
            "max_cvss": max(
                (
                    float(str(severity.get("score") or 0.0))
                    for item in vuln_list
                    for severity in (item.get("severity") or [])
                    if isinstance(severity, dict)
                ),
                default=0.0,
            ),
            "sample_ids": [
                str(item.get("id") or "") for item in vuln_list[:5] if str(item.get("id") or "")
            ],
        },
        "source_attribution": [
            attributed_source(
                "osv.dev",
                mode="remote",
                description="Package vulnerability correlation from the OSV API.",
                subject=package,
                evidence_count=len(vuln_list),
                cache_mode="http-ttl",
                cache_ttl_s=6 * 3600,
                rate_limit_hint="provider-managed",
            )
        ],
    }
    payload["coverage"] = coverage_summary(
        package,
        evidence_count=len(vuln_list),
        confidence="high" if vuln_list else "limited",
        providers=["osv.dev"],
    )
    payload.update(
        _base_payload(
            case_dir=case_dir,
            output=output,
            input_paths=input_paths,
            category="intel-cve",
            source_command="intel cve",
        )
    )
    return payload


def virustotal_payload(
    indicator: str,
    report: dict[str, Any],
    *,
    indicator_type: str = "file",
    case_dir: pathlib.Path | None = None,
    output: pathlib.Path | None = None,
    input_paths: list[str] | None = None,
) -> dict[str, Any]:
    configured, source = _secret_status("VT_API_KEY")
    attributes = report.get("attributes") if isinstance(report, dict) else None
    stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
    summary = cast(
        dict[str, Any], report.get("summary") if isinstance(report.get("summary"), dict) else {}
    )
    malicious_count = (
        int(summary.get("malicious_count") or int((stats or {}).get("malicious") or 0))
        if isinstance(summary, dict)
        else 0
    )
    suspicious_count = (
        int(summary.get("suspicious_count") or int((stats or {}).get("suspicious") or 0))
        if isinstance(summary, dict)
        else 0
    )
    engine_total = int(summary.get("engine_total") or 0) if isinstance(summary, dict) else 0
    detection_ratio = (
        float(summary.get("detection_ratio") or 0.0) if isinstance(summary, dict) else 0.0
    )
    payload = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "hash": indicator if indicator_type == "file" else None,
        "report": report,
        "summary": {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "keys": sorted(report.keys()) if isinstance(report, dict) else [],
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "engine_total": engine_total,
            "detection_ratio": detection_ratio,
            "detection_ratio_text": str(
                summary.get("detection_ratio_text")
                or (
                    f"{malicious_count + suspicious_count}/{engine_total}"
                    if engine_total
                    else "0/0"
                )
            ),
            "confidence_score": int(summary.get("confidence_score") or 0),
        },
        "source_attribution": [
            attributed_source(
                "virustotal",
                mode="remote",
                description=f"External {indicator_type} reputation lookup via VirusTotal.",
                subject=indicator,
                evidence_count=malicious_count + suspicious_count,
                credential_required=True,
                credential_configured=configured,
                credential_source=source,
                rate_limit_hint="provider-managed",
            )
        ],
    }
    payload["coverage"] = coverage_summary(
        indicator,
        evidence_count=malicious_count + suspicious_count,
        confidence="high"
        if configured and detection_ratio >= 0.15
        else ("moderate" if configured else "limited"),
        providers=["virustotal"],
    )
    payload.update(
        _base_payload(
            case_dir=case_dir,
            output=output,
            input_paths=input_paths,
            category="intel-virustotal",
            source_command="intel virustotal",
        )
    )
    return payload


def otx_payload(
    indicator: str,
    report: dict[str, Any],
    *,
    case_dir: pathlib.Path | None = None,
    output: pathlib.Path | None = None,
    input_paths: list[str] | None = None,
) -> dict[str, Any]:
    configured, source = _secret_status("OTX_API_KEY")
    pulses = report.get("pulse_info") if isinstance(report, dict) else None
    pulse_count = len((pulses or {}).get("pulses") or []) if isinstance(pulses, dict) else 0
    payload = {
        "indicator": indicator,
        "report": report,
        "summary": {
            "indicator": indicator,
            "keys": sorted(report.keys()) if isinstance(report, dict) else [],
            "pulse_count": pulse_count,
        },
        "source_attribution": [
            attributed_source(
                "alienvault-otx",
                mode="remote",
                description="External indicator reputation lookup via AlienVault OTX.",
                subject=indicator,
                evidence_count=pulse_count,
                credential_required=True,
                credential_configured=configured,
                credential_source=source,
                rate_limit_hint="provider-managed",
            )
        ],
    }
    payload["coverage"] = coverage_summary(
        indicator,
        evidence_count=pulse_count,
        confidence="moderate" if configured else "limited",
        providers=["alienvault-otx"],
    )
    payload.update(
        _base_payload(
            case_dir=case_dir,
            output=output,
            input_paths=input_paths,
            category="intel-otx",
            source_command="intel otx",
        )
    )
    return payload


def stix_payload(
    url: str,
    matches: list[dict[str, Any]],
    *,
    case_dir: pathlib.Path | None = None,
    output: pathlib.Path | None = None,
) -> dict[str, Any]:
    payload = {
        "url": url,
        "matches": matches,
        "summary": {"url": url, **_summarize_matches(matches)},
        "source_attribution": [
            attributed_source(
                "stix-feed",
                mode="remote",
                description="Downloaded STIX indicator feed parsed into IOC matches.",
                subject=url,
                evidence_count=len(matches),
                cache_mode="http-ttl",
                cache_ttl_s=6 * 3600,
                rate_limit_hint="provider-managed",
            )
        ],
    }
    payload["coverage"] = coverage_summary(
        url,
        evidence_count=len(matches),
        confidence="moderate" if matches else "limited",
        providers=["stix-feed"],
    )
    payload.update(
        _base_payload(
            case_dir=case_dir, output=output, category="intel-stix", source_command="intel stix"
        )
    )
    return payload


def taxii_payload(
    api_root: str,
    matches: list[dict[str, Any]],
    *,
    collection_id: str | None = None,
    limit: int | None = None,
    token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    case_dir: pathlib.Path | None = None,
    output: pathlib.Path | None = None,
) -> dict[str, Any]:
    credentials_present = bool(
        (token or "").strip() or ((username or "").strip() and (password or "").strip())
    )
    payload = {
        "api_root": api_root,
        "collection_id": collection_id,
        "matches": matches,
        "summary": {"api_root": api_root, "limit": limit, **_summarize_matches(matches)},
        "source_attribution": [
            attributed_source(
                "taxii-2.1",
                mode="remote",
                description="Remote TAXII collection indicator fetch and IOC parsing.",
                subject=collection_id or api_root,
                evidence_count=len(matches),
                credential_required=False,
                credential_configured=credentials_present,
                credential_source="prompt" if credentials_present else None,
                cache_mode="http-ttl",
                cache_ttl_s=10 * 60,
                rate_limit_hint="1 request/sec",
            )
        ],
    }
    payload["coverage"] = coverage_summary(
        collection_id or api_root,
        evidence_count=len(matches),
        confidence="moderate" if matches else "limited",
        providers=["taxii-2.1"],
    )
    payload.update(
        _base_payload(
            case_dir=case_dir, output=output, category="intel-taxii", source_command="intel taxii"
        )
    )
    return payload


def anomaly_payload(
    rows: list[dict[str, Any]],
    feature_keys: list[str],
    results: list[dict[str, Any]],
    *,
    input_path: pathlib.Path,
    case_dir: pathlib.Path | None = None,
    output: pathlib.Path | None = None,
) -> dict[str, Any]:
    payload = {
        "results": results,
        "summary": {
            "input_path": str(input_path),
            "row_count": len(rows),
            "feature_keys": feature_keys,
            "max_anomaly_score": max(
                (float(item.get("anomaly_score") or 0.0) for item in results), default=0.0
            ),
            "model_names": sorted(
                {
                    name
                    for item in results
                    for name in (
                        (item.get("models") or {}).keys()
                        if isinstance(item.get("models"), dict)
                        else []
                    )
                }
            ),
        },
        "explainability": _anomaly_explainability(rows, results, feature_keys),
        "source_attribution": [
            attributed_source(
                "lockknife-local-anomaly",
                mode="local",
                description="Local anomaly scoring over investigator-selected numeric features.",
                subject=str(input_path),
                evidence_count=len(results),
            )
        ],
        "advisory": "AI anomaly scoring is assistive triage only; confirm any outliers against underlying evidence.",
    }
    payload["coverage"] = coverage_summary(
        str(input_path),
        evidence_count=len(results),
        confidence="moderate" if results else "limited",
        providers=["lockknife-local-anomaly"],
    )
    payload.update(
        _base_payload(
            case_dir=case_dir,
            output=output,
            input_paths=[str(input_path)],
            category="ai-anomaly",
            source_command="ai anomaly",
        )
    )
    return payload


def password_payload(
    predictions: list[str],
    *,
    wordlist_path: pathlib.Path,
    source_words: list[str],
    min_len: int,
    max_len: int,
    seed: int | None,
    metadata: dict[str, Any] | None = None,
    case_dir: pathlib.Path | None = None,
    output: pathlib.Path | None = None,
) -> dict[str, Any]:
    metadata = metadata or {}
    payload = {
        "predictions": predictions,
        "summary": {
            "wordlist": str(wordlist_path),
            "generated_count": len(predictions),
            "source_word_count": len(source_words),
            "min_len": min_len,
            "max_len": max_len,
            "seed": seed,
            **metadata,
        },
        "explainability": _password_explainability(source_words, predictions),
        "source_attribution": [
            attributed_source(
                "lockknife-local-password-model",
                mode="local",
                description="Local Markov-style password generation trained from the supplied wordlist.",
                subject=str(wordlist_path),
                evidence_count=len(predictions),
            )
        ],
        "advisory": "Generated password candidates are heuristic guesses only and should not be treated as validated credentials.",
    }
    payload["coverage"] = coverage_summary(
        str(wordlist_path),
        evidence_count=len(predictions),
        confidence="moderate" if predictions else "limited",
        providers=["lockknife-local-password-model"],
    )
    payload.update(
        _base_payload(
            case_dir=case_dir,
            output=output,
            input_paths=[str(wordlist_path)]
            + ([str(metadata["personal_data_path"])] if metadata.get("personal_data_path") else []),
            category="ai-password-predictions",
            source_command="ai predict-password",
        )
    )
    return payload
