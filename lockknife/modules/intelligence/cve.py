from __future__ import annotations

import re

from typing import Any

from lockknife.core.http import http_post_json
from lockknife.core.logging import get_logger

log = get_logger()


ANDROID_SDK_CVE_MATRIX: dict[int, dict[str, Any]] = {
    23: {"android_version": "6.0", "risk": "critical", "score": 92, "support_status": "eol", "known_cves": ["CVE-2019-2215", "CVE-2020-0069"]},
    24: {"android_version": "7.0", "risk": "critical", "score": 90, "support_status": "eol", "known_cves": ["CVE-2020-0022", "CVE-2020-0069"]},
    25: {"android_version": "7.1", "risk": "critical", "score": 88, "support_status": "eol", "known_cves": ["CVE-2020-0458", "CVE-2020-0114"]},
    26: {"android_version": "8.0", "risk": "high", "score": 80, "support_status": "eol", "known_cves": ["CVE-2021-0394", "CVE-2021-39675"]},
    27: {"android_version": "8.1", "risk": "high", "score": 78, "support_status": "eol", "known_cves": ["CVE-2021-39674", "CVE-2021-39685"]},
    28: {"android_version": "9", "risk": "high", "score": 74, "support_status": "eol", "known_cves": ["CVE-2022-20186", "CVE-2022-20210"]},
    29: {"android_version": "10", "risk": "medium", "score": 60, "support_status": "extended-support", "known_cves": ["CVE-2023-20963", "CVE-2023-21108"]},
    30: {"android_version": "11", "risk": "medium", "score": 55, "support_status": "extended-support", "known_cves": ["CVE-2023-21273", "CVE-2023-21127"]},
    31: {"android_version": "12", "risk": "medium", "score": 45, "support_status": "supported", "known_cves": ["CVE-2024-0031"]},
    32: {"android_version": "12L", "risk": "medium", "score": 42, "support_status": "supported", "known_cves": ["CVE-2024-0044"]},
    33: {"android_version": "13", "risk": "low", "score": 34, "support_status": "supported", "known_cves": ["CVE-2024-31317"]},
    34: {"android_version": "14", "risk": "low", "score": 25, "support_status": "supported", "known_cves": ["CVE-2024-31320"]},
    35: {"android_version": "15", "risk": "low", "score": 18, "support_status": "current", "known_cves": []},
}

KERNEL_BRANCH_CVE_MATRIX: dict[str, dict[str, Any]] = {
    "3.18": {"risk": "critical", "score": 92, "support_status": "eol", "known_cves": ["CVE-2019-2215", "CVE-2021-1048"]},
    "4.4": {"risk": "critical", "score": 88, "support_status": "eol", "known_cves": ["CVE-2020-0069", "CVE-2022-0435"]},
    "4.9": {"risk": "high", "score": 78, "support_status": "eol", "known_cves": ["CVE-2022-0847", "CVE-2023-0266"]},
    "4.14": {"risk": "high", "score": 72, "support_status": "extended-support", "known_cves": ["CVE-2023-32233", "CVE-2024-1086"]},
    "4.19": {"risk": "medium", "score": 62, "support_status": "extended-support", "known_cves": ["CVE-2023-42755", "CVE-2024-1086"]},
    "5.4": {"risk": "medium", "score": 54, "support_status": "supported", "known_cves": ["CVE-2023-0386", "CVE-2024-1086"]},
    "5.10": {"risk": "medium", "score": 46, "support_status": "supported", "known_cves": ["CVE-2024-1086"]},
    "5.15": {"risk": "low", "score": 34, "support_status": "supported", "known_cves": ["CVE-2024-26656"]},
    "6.1": {"risk": "low", "score": 24, "support_status": "current", "known_cves": []},
}


def query_osv(query: str) -> dict[str, Any]:
    out = http_post_json("https://api.osv.dev/v1/query", {"query": query}, timeout_s=15.0, max_attempts=4, cache_ttl_s=6 * 3600)
    return out if isinstance(out, dict) else {"raw": out}


def correlate_cves_for_apk_package(package: str) -> dict[str, Any]:
    return query_osv(package)


def correlate_cves_for_kernel_version(kernel_version: str) -> dict[str, Any]:
    branch = _kernel_branch(kernel_version)
    profile = KERNEL_BRANCH_CVE_MATRIX.get(branch, {})
    return {
        "kernel_version": kernel_version,
        "kernel_branch": branch,
        "risk": profile.get("risk", "unknown"),
        "score": profile.get("score", 0),
        "support_status": profile.get("support_status", "unknown"),
        "known_cves": list(profile.get("known_cves") or []),
        "mapping_confidence": "high" if branch in KERNEL_BRANCH_CVE_MATRIX else "limited",
    }


def android_cve_risk_score(sdk: int) -> dict[str, Any]:
    profile = ANDROID_SDK_CVE_MATRIX.get(int(sdk), {})
    av = profile.get("android_version")
    query = f"Android {av}" if av else f"Android SDK {sdk}"
    osv = {}
    try:
        osv = query_osv(query)
    except Exception:
        log.warning("osv_query_failed", exc_info=True, query=query)
        osv = {}
    vulns = osv.get("vulns") if isinstance(osv, dict) else None
    count = len(vulns) if isinstance(vulns, list) else 0

    max_score = 0.0
    for v in vulns or []:
        if not isinstance(v, dict):
            continue
        severities = v.get("severity")
        if not isinstance(severities, list):
            continue
        for sev in severities:
            if not isinstance(sev, dict):
                continue
            score = sev.get("score")
            if score is None:
                continue
            try:
                s = float(str(score))
            except Exception:
                log.debug("cvss_score_parse_failed", exc_info=True, score=score, query=query)
                continue
            if s > max_score:
                max_score = s

    risk = str(profile.get("risk") or "unknown")
    score_i = int(profile.get("score") or 0)
    if max_score >= 9.0:
        risk, score_i = "critical", 90
    elif max_score >= 7.0:
        risk, score_i = "high", 75
    elif max_score >= 4.0:
        risk, score_i = "medium", 55
    elif max_score > 0.0:
        risk, score_i = "low", 35
    elif sdk <= 0:
        risk, score_i = "unknown", 0

    return {
        "sdk": sdk,
        "android_version": av,
        "risk": risk,
        "score": score_i,
        "support_status": profile.get("support_status", "unknown"),
        "known_cves": list(profile.get("known_cves") or []),
        "mapping_confidence": "high" if profile else "limited",
        "osv_query": query,
        "osv_vuln_count": count,
        "osv_max_cvss": max_score if max_score > 0.0 else None,
    }


def _kernel_branch(kernel_version: str) -> str:
    match = re.search(r"([0-9]+\.[0-9]+)", kernel_version or "")
    return match.group(1) if match else "unknown"
