from __future__ import annotations

import dataclasses
import pathlib
from typing import Any

from lockknife.modules.apk.decompile import parse_apk_manifest
from lockknife.modules.apk.permissions import score_permissions
from lockknife.modules.apk._risk_summary import build_apk_risk_summary
from lockknife.modules.security.owasp import mastg_summary


@dataclasses.dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    title: str
    details: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class ApkAnalysisReport:
    package: str | None
    manifest: dict[str, Any]
    findings: list[Finding]
    permission_risk: dict[str, Any]
    risk_summary: dict[str, Any]
    mastg: dict[str, Any]
    dex_header_count: int = 0


def _int_value(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except Exception:
        return None


def scan_apk(apk_path: pathlib.Path) -> list[Finding]:
    info = parse_apk_manifest(apk_path)
    return findings_from_manifest(info)


def findings_from_manifest(info: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    if info.get("debuggable") is True:
        findings.append(Finding(id="debuggable", severity="high", title="App is debuggable", details={}))

    if info.get("uses_cleartext_traffic") in {"true", True}:
        findings.append(
            Finding(
                id="cleartext",
                severity="medium",
                title="Uses cleartext traffic",
                details={"usesCleartextTraffic": info.get("uses_cleartext_traffic")},
            )
        )

    if info.get("allow_backup") in {"true", True}:
        findings.append(
            Finding(
                id="allow_backup",
                severity="medium",
                title="AllowBackup enabled",
                details={"allowBackup": info.get("allow_backup")},
            )
        )

    sdk = info.get("sdk") or {}
    min_sdk = _int_value(sdk.get("min"))
    target_sdk = _int_value(sdk.get("target"))
    if target_sdk is not None and target_sdk < 30:
        findings.append(
            Finding(
                id="legacy_target_sdk",
                severity="high" if target_sdk < 28 else "medium",
                title="Target SDK is behind current platform hardening baselines",
                details={"target_sdk": target_sdk},
            )
        )
    if min_sdk is not None and min_sdk < 24:
        findings.append(
            Finding(
                id="legacy_min_sdk",
                severity="medium",
                title="Minimum SDK allows legacy Android attack surface",
                details={"min_sdk": min_sdk},
            )
        )

    component_summary = info.get("component_summary") or {}
    components = info.get("components") or {}
    interactions = (components.get("interaction_analysis") if isinstance(components, dict) else None) or {}
    exported_total = int(component_summary.get("exported_total") or 0)
    if exported_total:
        findings.append(
            Finding(
                id="exported_components",
                severity="medium" if exported_total < 4 else "high",
                title="APK exposes exported Android components",
                details={"exported_total": exported_total, "summary": component_summary},
            )
        )

    browsable_total = int(component_summary.get("browsable_deeplink_total") or 0)
    if browsable_total:
        findings.append(
            Finding(
                id="browsable_deeplinks",
                severity="medium",
                title="Browsable deep links are present",
                details={"browsable_deeplink_total": browsable_total, "deeplinks": info.get("deeplinks") or []},
            )
        )

    weak_providers = [
        provider
        for provider in components.get("providers") or []
        if provider.get("exported")
        and not provider.get("read_permission")
        and not provider.get("write_permission")
    ]
    if weak_providers:
        findings.append(
            Finding(
                id="weak_exported_provider",
                severity="high",
                title="Exported content provider lacks explicit read/write guards",
                details={
                    "providers": [provider.get("name") for provider in weak_providers],
                    "count": len(weak_providers),
                },
            )
        )

    overlap_groups = interactions.get("overlaps") or []
    if overlap_groups:
        findings.append(
            Finding(
                id="intent_filter_overlap",
                severity="medium",
                title="Intent-filter or deep-link overlap detected across components",
                details={"count": len(overlap_groups), "overlaps": overlap_groups[:8]},
            )
        )

    permission_gaps = interactions.get("permission_gaps") or []
    if permission_gaps:
        findings.append(
            Finding(
                id="component_permission_gap",
                severity="high",
                title="Exported components expose interaction surface without permission enforcement",
                details={"count": len(permission_gaps), "components": permission_gaps[:8]},
            )
        )

    custom_scheme_overlaps = interactions.get("custom_scheme_overlaps") or []
    if custom_scheme_overlaps:
        findings.append(
            Finding(
                id="custom_scheme_collision",
                severity="medium",
                title="Custom URI scheme overlap may create ambiguous routing",
                details={"count": len(custom_scheme_overlaps), "schemes": custom_scheme_overlaps},
            )
        )

    strings = info.get("string_analysis") or {}
    secret_count = int(((strings.get("stats") or {}).get("secret_indicator_count") or 0))
    if secret_count:
        findings.append(
            Finding(
                id="hardcoded_secret",
                severity="high",
                title="Archive contains hardcoded secret indicators",
                details={"count": secret_count, "matches": strings.get("hardcoded_secret_indicators") or []},
            )
        )

    signing = info.get("signing") or {}
    if signing.get("has_debug_or_test_certificate"):
        findings.append(
            Finding(
                id="test_keys",
                severity="high",
                title="Debug or test signing indicators detected",
                details={"certificates": signing.get("certificates") or [], "meta_inf_signers": signing.get("meta_inf_signers")},
            )
        )

    strict_signing = signing.get("strict_verification") or {}
    if any(item.get("id") == "legacy-v1-only-signing" for item in strict_signing.get("findings") or [] if isinstance(item, dict)):
        findings.append(
            Finding(
                id="legacy_v1_only_signing",
                severity="medium",
                title="APK appears to rely on legacy v1-only signing",
                details={"strict_verification": strict_signing},
            )
        )

    trackers = strings.get("trackers") or []
    if trackers:
        findings.append(
            Finding(
                id="tracker_sdk_present",
                severity="low",
                title="Tracker or analytics SDK markers detected",
                details={"trackers": trackers[:6], "count": len(trackers)},
            )
        )

    code_signals = strings.get("code_signals") or []
    dynamic_loading = [item for item in code_signals if isinstance(item, dict) and item.get("id") == "dynamic-code-loading"]
    if dynamic_loading:
        findings.append(
            Finding(
                id="dynamic_code_loading",
                severity="medium",
                title="Dynamic code loading indicators detected",
                details={"signals": dynamic_loading},
            )
        )

    webview_bridge = [item for item in code_signals if isinstance(item, dict) and item.get("id") == "webview-js-bridge"]
    if webview_bridge:
        findings.append(
            Finding(
                id="webview_js_bridge",
                severity="medium",
                title="WebView JavaScript bridge indicators detected",
                details={"signals": webview_bridge},
            )
        )

    insecure_storage = [item for item in code_signals if isinstance(item, dict) and item.get("id") == "insecure-storage-world-readable"]
    if insecure_storage:
        findings.append(
            Finding(
                id="insecure_storage_world_readable",
                severity="high",
                title="World-readable or world-writable storage APIs detected",
                details={"signals": insecure_storage},
            )
        )

    crypto_ecb = [item for item in code_signals if isinstance(item, dict) and item.get("id") == "crypto-ecb-mode"]
    if crypto_ecb:
        findings.append(
            Finding(
                id="crypto_ecb_mode",
                severity="high",
                title="ECB-mode cryptography indicators detected",
                details={"signals": crypto_ecb},
            )
        )

    crypto_static_iv = [item for item in code_signals if isinstance(item, dict) and item.get("id") == "crypto-static-iv"]
    if crypto_static_iv:
        findings.append(
            Finding(
                id="crypto_static_iv",
                severity="high",
                title="Static IV cryptography indicators detected",
                details={"signals": crypto_static_iv},
            )
        )

    native_libraries = strings.get("native_libraries") or []
    if native_libraries:
        findings.append(
            Finding(
                id="native_library_surface",
                severity="info",
                title="Native libraries and JNI entry points detected",
                details={
                    "count": len(native_libraries),
                    "libraries": native_libraries[:8],
                    "jni_entry_point_count": int(((strings.get("stats") or {}).get("jni_entry_point_count") or 0)),
                },
            )
        )

    if int(((strings.get("stats") or {}).get("certificate_pin_indicator_count") or 0)):
        findings.append(
            Finding(
                id="certificate_pinning_indicators",
                severity="info",
                title="Certificate pinning indicators were found in archive strings",
                details={"matches": strings.get("certificate_pin_indicators") or []},
            )
        )

    permissions = set(info.get("permissions") or [])
    if {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS"}.intersection(permissions):
        findings.append(
            Finding(
                id="sms_privilege_surface",
                severity="medium",
                title="SMS-related dangerous permissions present",
                details={"permissions": sorted(permission for permission in permissions if "SMS" in permission)},
            )
        )

    if info.get("network_security_config"):
        findings.append(
            Finding(
                id="network_security_config",
                severity="info",
                title="Custom network security configuration declared",
                details={"network_security_config": info.get("network_security_config")},
            )
        )

    if not info.get("permissions"):
        findings.append(Finding(id="no_permissions", severity="low", title="No runtime permissions declared", details={}))

    return findings


def analyze_apk(apk_path: pathlib.Path) -> ApkAnalysisReport:
    manifest = parse_apk_manifest(apk_path)
    findings = findings_from_manifest(manifest)
    permission_score, risks = score_permissions(list(manifest.get("permissions") or []))
    risk_summary = build_apk_risk_summary(manifest, findings, permission_score)
    permission_risk = {
        "score": permission_score,
        "risks": [dataclasses.asdict(risk) for risk in risks],
    }
    mastg = mastg_summary([dataclasses.asdict(finding) for finding in findings])
    return ApkAnalysisReport(
        package=manifest.get("package"),
        manifest=manifest,
        findings=findings,
        permission_risk=permission_risk,
        risk_summary=risk_summary,
        mastg=mastg,
    )

