from __future__ import annotations

import dataclasses
from typing import Any

OWASP_MOBILE_MAPPINGS: dict[str, dict[str, Any]] = {
    "debuggable": {
        "mastg": ["MSTG-RESILIENCE-1", "MSTG-RESILIENCE-2"],
        "owasp_mobile": ["M10: Extraneous Functionality"],
        "note": "Debuggable builds and similar toggles expand local attack and reverse-engineering opportunities.",
    },
    "allow_backup_enabled": {
        "mastg": ["MSTG-STORAGE-2"],
        "owasp_mobile": ["M2: Insecure Data Storage"],
        "note": "Backups can expose application data or tokens to local extraction workflows.",
    },
    "allow_backup": {
        "mastg": ["MSTG-STORAGE-2"],
        "owasp_mobile": ["M2: Insecure Data Storage"],
        "note": "Backups can expose application data or tokens to local extraction workflows.",
    },
    "exported_components": {
        "mastg": ["MSTG-PLATFORM-2", "MSTG-PLATFORM-8"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "Exported activities, services, receivers, or providers create externally reachable platform entry points.",
    },
    "weak_exported_provider": {
        "mastg": ["MSTG-PLATFORM-8", "MSTG-STORAGE-2"],
        "owasp_mobile": ["M1: Improper Platform Usage", "M2: Insecure Data Storage"],
        "note": "Weak provider permission models often turn directly into data disclosure or unsafe IPC paths.",
    },
    "browsable_deeplinks": {
        "mastg": ["MSTG-PLATFORM-3", "MSTG-PLATFORM-8"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "Browsable deep links should be reviewed as externally triggerable routing and auth boundaries.",
    },
    "intent_filter_overlap": {
        "mastg": ["MSTG-PLATFORM-3", "MSTG-PLATFORM-8"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "Intent-filter overlap can create ambiguous routing, hijack opportunities, or unexpected entry-point selection.",
    },
    "custom_scheme_collision": {
        "mastg": ["MSTG-PLATFORM-3"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "Custom scheme reuse across components should be reviewed for hijack and confusion risks.",
    },
    "component_permission_gap": {
        "mastg": ["MSTG-PLATFORM-2", "MSTG-PLATFORM-8"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "Exported surface without explicit permission enforcement often becomes reachable IPC or routing abuse.",
    },
    "live_deeplink_resolution": {
        "mastg": ["MSTG-PLATFORM-3"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "On-device resolution confirms the deep-link route is reachable in practice.",
    },
    "live_provider_resolution": {
        "mastg": ["MSTG-PLATFORM-8", "MSTG-STORAGE-2"],
        "owasp_mobile": ["M1: Improper Platform Usage", "M2: Insecure Data Storage"],
        "note": "Live provider resolution is strong evidence that the provider attack path is reachable.",
    },
    "live_component_resolution": {
        "mastg": ["MSTG-PLATFORM-8"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "Live component resolution confirms exported entry points are visible to the package manager.",
    },
    "live_component_permission_gap": {
        "mastg": ["MSTG-PLATFORM-2", "MSTG-PLATFORM-8"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "On-device resolution with no declared permission guard is strong evidence of reachable IPC or routing exposure.",
    },
    "cleartext_traffic": {
        "mastg": ["MSTG-NETWORK-1", "MSTG-NETWORK-2"],
        "owasp_mobile": ["M3: Insecure Communication"],
        "note": "Cleartext transport or unsafe trust configuration weakens network protections.",
    },
    "cleartext": {
        "mastg": ["MSTG-NETWORK-1", "MSTG-NETWORK-2"],
        "owasp_mobile": ["M3: Insecure Communication"],
        "note": "Cleartext transport or unsafe trust configuration weakens network protections.",
    },
    "network_security_config": {
        "mastg": ["MSTG-NETWORK-2"],
        "owasp_mobile": ["M3: Insecure Communication"],
        "note": "Review custom trust anchors, domain configs, and cleartext allowances.",
    },
    "debuggable_app": {
        "mastg": ["MSTG-RESILIENCE-1", "MSTG-RESILIENCE-2"],
        "owasp_mobile": ["M10: Extraneous Functionality"],
        "note": "Debuggable builds and similar toggles expand local attack and reverse-engineering opportunities.",
    },
    "debug_or_test_signing": {
        "mastg": ["MSTG-RESILIENCE-1", "MSTG-CODE-1"],
        "owasp_mobile": ["M10: Extraneous Functionality"],
        "note": "Non-production signing and debug posture should be treated as shipping misconfiguration risk.",
    },
    "hardcoded_secret": {
        "mastg": ["MSTG-STORAGE-1", "MSTG-CRYPTO-1"],
        "owasp_mobile": ["M5: Insufficient Cryptography", "M2: Insecure Data Storage"],
        "note": "Embedded secrets typically weaken both storage and crypto trust assumptions.",
    },
    "insecure_storage_world_readable": {
        "mastg": ["MSTG-STORAGE-2"],
        "owasp_mobile": ["M2: Insecure Data Storage"],
        "note": "World-readable or world-writable storage is a direct storage isolation failure.",
    },
    "crypto_ecb_mode": {
        "mastg": ["MSTG-CRYPTO-2"],
        "owasp_mobile": ["M5: Insufficient Cryptography"],
        "note": "ECB mode is not semantically secure and should fail modern crypto review.",
    },
    "crypto_static_iv": {
        "mastg": ["MSTG-CRYPTO-2"],
        "owasp_mobile": ["M5: Insufficient Cryptography"],
        "note": "Static IV reuse breaks the assumptions of many symmetric encryption modes.",
    },
    "webview_js_bridge_exposed": {
        "mastg": ["MSTG-PLATFORM-7"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "JavaScript bridges expand WebView attack surface and should be reviewed for origin trust and method exposure.",
    },
    "sms_privilege_surface": {
        "mastg": ["MSTG-PLATFORM-1", "MSTG-PLATFORM-2"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "High-risk SMS/telephony permission bundles deserve explicit least-privilege review.",
    },
    "selinux_permissive": {
        "mastg": ["MSTG-PLATFORM-8", "MSTG-RESILIENCE-3"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "A permissive SELinux posture weakens OS-level isolation assumptions around the target environment.",
    },
    "selinux_permissive_domain": {
        "mastg": ["MSTG-PLATFORM-8", "MSTG-RESILIENCE-3"],
        "owasp_mobile": ["M1: Improper Platform Usage"],
        "note": "Permissive SELinux domains weaken enforcement for the affected process types even if the overall device is enforcing.",
    },
}


MASVS_CHECKLIST = {
    "PLATFORM": [
        {
            "id": "PLATFORM-ENTRYPOINTS",
            "title": "Exported components are protected",
            "fails_on": {
                "exported_components",
                "component_permission_gap",
                "live_component_permission_gap",
            },
        },
        {
            "id": "PLATFORM-DEEPLINKS",
            "title": "Deep links are unambiguous and constrained",
            "fails_on": {
                "browsable_deeplinks",
                "intent_filter_overlap",
                "custom_scheme_collision",
                "live_deeplink_resolution",
            },
        },
        {
            "id": "PLATFORM-PROVIDERS",
            "title": "Providers enforce authorities and caller restrictions",
            "fails_on": {"weak_exported_provider", "live_provider_resolution"},
        },
    ],
    "STORAGE": [
        {
            "id": "STORAGE-BACKUP",
            "title": "Backups are disabled or justified",
            "fails_on": {"allow_backup_enabled", "allow_backup"},
        },
        {
            "id": "STORAGE-ACCESS",
            "title": "Storage is not world-readable or world-writable",
            "fails_on": {"insecure_storage_world_readable"},
        },
        {
            "id": "STORAGE-SECRETS",
            "title": "Secrets are not hard-coded into the app",
            "fails_on": {"hardcoded_secret"},
        },
    ],
    "NETWORK": [
        {
            "id": "NETWORK-CLEARTEXT",
            "title": "Cleartext transport is disabled",
            "fails_on": {"cleartext_traffic", "cleartext"},
        },
        {
            "id": "NETWORK-TRUST",
            "title": "Trust configuration is tightly scoped",
            "fails_on": {"network_security_config"},
        },
    ],
    "CRYPTO": [
        {
            "id": "CRYPTO-SECRETS",
            "title": "Cryptographic keys and secrets are not embedded",
            "fails_on": {"hardcoded_secret"},
        },
        {
            "id": "CRYPTO-MODES",
            "title": "Cryptography avoids ECB and static IV patterns",
            "fails_on": {"crypto_ecb_mode", "crypto_static_iv"},
        },
    ],
    "RESILIENCE": [
        {
            "id": "RESILIENCE-DEBUG",
            "title": "Debuggable posture is disabled in production",
            "fails_on": {"debuggable", "debuggable_app", "debug_or_test_signing"},
        },
        {
            "id": "RESILIENCE-SEPOLICY",
            "title": "SELinux posture remains enforced for relevant domains",
            "fails_on": {"selinux_permissive", "selinux_permissive_domain"},
        },
        {
            "id": "RESILIENCE-WEBVIEW",
            "title": "WebView bridges are minimized and reviewed",
            "fails_on": {"webview_js_bridge_exposed"},
        },
    ],
}


@dataclasses.dataclass(frozen=True)
class MastgMapping:
    finding_id: str
    mastg: list[str]
    owasp_mobile: list[str]
    title: str | None = None
    severity: str | None = None
    evidence: list[str] = dataclasses.field(default_factory=list)
    note: str | None = None


def map_findings_to_mastg(findings: list[dict[str, Any]]) -> list[MastgMapping]:
    mappings: list[MastgMapping] = []
    for finding in findings:
        finding_id = _normalize_finding_id(finding.get("id"))
        if not finding_id:
            continue
        mapping = OWASP_MOBILE_MAPPINGS.get(finding_id)
        if mapping is None:
            continue
        mappings.append(
            MastgMapping(
                finding_id=finding_id,
                mastg=list(mapping.get("mastg") or []),
                owasp_mobile=list(mapping.get("owasp_mobile") or []),
                title=_string_value(finding.get("title")),
                severity=_string_value(finding.get("severity")),
                evidence=_extract_evidence(finding),
                note=_string_value(mapping.get("note")),
            )
        )
    return mappings


def mastg_summary(artifacts: Any) -> dict[str, Any]:
    findings = _collect_finding_records(artifacts)
    mappings = map_findings_to_mastg(findings)
    scorecard = _masvs_scorecard(findings)
    mastg_ids = sorted({mastg_id for item in mappings for mastg_id in item.mastg})
    owasp_categories = sorted({category for item in mappings for category in item.owasp_mobile})
    mapped_ids = {item.finding_id for item in mappings}
    unmapped_ids = {
        normalized_id
        for finding in findings
        if (normalized_id := _normalize_finding_id(finding.get("id"))) is not None
    }
    unmapped = sorted(unmapped_ids - mapped_ids)
    return {
        "mastg_ids": mastg_ids,
        "owasp_categories": owasp_categories,
        "mappings": [dataclasses.asdict(item) for item in mappings],
        "coverage": {
            "finding_total": len(findings),
            "mapped_finding_total": len(mappings),
            "mastg_total": len(mastg_ids),
            "owasp_total": len(owasp_categories),
            "unmapped_findings": unmapped,
        },
        "evidence_links": [
            {"finding_id": item.finding_id, "title": item.title, "evidence": item.evidence}
            for item in mappings
            if item.evidence
        ],
        "review_focus": _review_focus(mappings, scorecard),
        "masvs_scorecard": scorecard,
    }


def _collect_finding_records(value: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if value.get("id") is not None:
            findings.append(value)
        for nested in value.values():
            findings.extend(_collect_finding_records(nested))
    elif isinstance(value, list):
        for item in value:
            findings.extend(_collect_finding_records(item))
    return findings


def _extract_evidence(finding: dict[str, Any]) -> list[str]:
    evidence = finding.get("evidence")
    if isinstance(evidence, list):
        return [str(item) for item in evidence[:5]]
    details_obj = finding.get("details")
    details = details_obj if isinstance(details_obj, dict) else {}
    for key in ("providers", "deeplinks"):
        values = details.get(key)
        if isinstance(values, list):
            return [str(item) for item in values[:5]]
    summary = details.get("summary")
    if isinstance(summary, dict):
        return [f"{key}={value}" for key, value in list(summary.items())[:5]]
    return []


def _normalize_finding_id(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().lower().replace("-", "_")


def _string_value(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _review_focus(mappings: list[MastgMapping], scorecard: dict[str, Any]) -> list[str]:
    failing_areas = [
        item["area"] for item in scorecard.get("areas") or [] if item.get("fail_count")
    ]
    if failing_areas:
        return failing_areas[:6]
    families = sorted(
        {mastg_id.split("-")[1] for item in mappings for mastg_id in item.mastg if "-" in mastg_id}
    )
    return families[:6]


def _masvs_scorecard(findings: list[dict[str, Any]]) -> dict[str, Any]:
    finding_ids = {_normalize_finding_id(item.get("id")) for item in findings}
    finding_ids.discard(None)
    evidence_map = {
        normalized: _extract_evidence(item)
        for item in findings
        if (normalized := _normalize_finding_id(item.get("id"))) is not None
    }
    areas: list[dict[str, Any]] = []
    total_checks = 0
    total_pass = 0
    total_fail = 0
    for area, checks in MASVS_CHECKLIST.items():
        rendered_checks: list[dict[str, Any]] = []
        pass_count = 0
        fail_count = 0
        for check in checks:
            fails_on = {str(item) for item in check["fails_on"]}
            matched = sorted(fails_on & finding_ids)
            status = "fail" if matched else "pass"
            if status == "pass":
                pass_count += 1
            else:
                fail_count += 1
            rendered_checks.append(
                {
                    "id": check["id"],
                    "title": check["title"],
                    "status": status,
                    "triggered_by": matched,
                    "evidence": [
                        evidence
                        for finding_id in matched
                        for evidence in evidence_map.get(finding_id, [])
                    ][:5],
                }
            )
        total_checks += len(checks)
        total_pass += pass_count
        total_fail += fail_count
        score = int(round((pass_count / len(checks)) * 100)) if checks else 100
        areas.append(
            {
                "area": area,
                "score": score,
                "check_total": len(checks),
                "pass_count": pass_count,
                "fail_count": fail_count,
                "status": "fail" if fail_count else "pass",
                "checks": rendered_checks,
            }
        )
    overall_score = int(round((total_pass / total_checks) * 100)) if total_checks else 100
    return {
        "overall_score": overall_score,
        "check_total": total_checks,
        "pass_count": total_pass,
        "fail_count": total_fail,
        "status": "fail" if total_fail else "pass",
        "areas": areas,
    }
