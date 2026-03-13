from __future__ import annotations

import pathlib
from typing import Any

from defusedxml.ElementTree import ParseError, fromstring

from lockknife.core.serialize import write_json
from lockknife.modules.apk._code_signals import scan_archive_code_signals
from lockknife.modules.apk._decompile_archive import archive_inventory
from lockknife.modules.apk._decompile_dex import extract_dex_headers_impl
from lockknife.modules.apk._decompile_inspection import _android_attr, _apk_method, _clean_strings, _coerce_manifest_bool, _normalize_component_name
from lockknife.modules.apk._decompile_shared import ANDROID_ATTR, ANDROID_NS, ApkError, SUPPORTED_DECOMPILE_MODES, TEXT_FILE_SUFFIXES, _require_androguard
from lockknife.modules.apk._decompile_tools import available_decompile_tools, run_decompile_pipeline
from lockknife.modules.apk._manifest_components import component_details
from lockknife.modules.apk._signing import signing_summary



lockknife_core = None



def parse_apk_manifest(apk_path: pathlib.Path) -> dict[str, Any]:
    APK = _require_androguard()
    apk_obj = APK(str(apk_path))
    manifest = apk_obj.get_android_manifest_xml()
    manifest_xml = manifest.toxml() if manifest is not None else None
    package = _apk_method(apk_obj, "get_package")
    permissions = sorted(set(_clean_strings(_apk_method(apk_obj, "get_permissions", []))))
    target_sdk = _apk_method(apk_obj, "get_target_sdk_version")
    components = component_details(manifest_xml, package, target_sdk=target_sdk)
    archive = archive_inventory(apk_path)
    strings = scan_archive_code_signals(apk_path)
    signing = signing_summary(apk_obj, apk_path)
    deeplinks = [
        str(item.get("uri"))
        for item in components.get("deeplinks") or []
        if isinstance(item, dict) and str(item.get("uri") or "").strip()
    ]

    info = {
        "package": package,
        "app_name": _apk_method(apk_obj, "get_app_name"),
        "main_activity": _normalize_component_name(package, _apk_method(apk_obj, "get_main_activity")),
        "version_name": _apk_method(apk_obj, "get_androidversion_name"),
        "version_code": _apk_method(apk_obj, "get_androidversion_code"),
        "sdk": {
            "min": _apk_method(apk_obj, "get_min_sdk_version"),
            "target": target_sdk,
            "max": _apk_method(apk_obj, "get_max_sdk_version"),
        },
        "permissions": permissions,
        "permission_details": _apk_method(apk_obj, "get_details_permissions", {}) or {},
        "features": sorted(set(_clean_strings(_apk_method(apk_obj, "get_features", [])))),
        "uses_libraries": sorted(set(_clean_strings(_apk_method(apk_obj, "get_libraries", [])))),
        "activities": _clean_strings(_apk_method(apk_obj, "get_activities", [])),
        "services": _clean_strings(_apk_method(apk_obj, "get_services", [])),
        "receivers": _clean_strings(_apk_method(apk_obj, "get_receivers", [])),
        "providers": _clean_strings(_apk_method(apk_obj, "get_providers", [])),
        "components": components,
        "component_summary": components.get("summary") or {},
        "component_interactions": components.get("interaction_analysis") or {},
        "deeplinks": sorted(set(deeplinks)),
        "manifest_xml": manifest_xml,
        "debuggable": bool(_apk_method(apk_obj, "is_debuggable", False)),
        "allow_backup": None,
        "uses_cleartext_traffic": None,
        "network_security_config": None,
        "backup_agent": None,
        "archive": archive,
        "string_analysis": strings,
        "code_signals": {
            "libraries": strings.get("libraries") or [],
            "trackers": strings.get("trackers") or [],
            "signals": strings.get("code_signals") or [],
        },
        "signing": signing,
    }

    if manifest_xml:
        try:
            root = fromstring(manifest_xml)
            app_node = root.find("application")
            info["allow_backup"] = _coerce_manifest_bool(_android_attr(app_node, "allowBackup"))
            info["uses_cleartext_traffic"] = _coerce_manifest_bool(_android_attr(app_node, "usesCleartextTraffic"))
            info["network_security_config"] = _android_attr(app_node, "networkSecurityConfig")
            info["backup_agent"] = _android_attr(app_node, "backupAgent")
            info["manifest_flags"] = {
                "debuggable": info["debuggable"],
                "allow_backup": info["allow_backup"],
                "uses_cleartext_traffic": info["uses_cleartext_traffic"],
                "network_security_config": info["network_security_config"],
                "backup_agent": info["backup_agent"],
            }
        except ParseError:
            pass

    return info



def decompile_apk_report(apk_path: pathlib.Path, output_dir: pathlib.Path, *, mode: str = "auto") -> dict[str, Any]:
    if not apk_path.exists():
        raise ApkError(f"APK not found: {apk_path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_info = parse_apk_manifest(apk_path)
    manifest_path = output_dir / "manifest.json"
    write_json(manifest_path, manifest_info)
    pipeline = run_decompile_pipeline(apk_path, output_dir, requested_mode=mode)

    report_path = output_dir / "decompile_report.json"
    report = {
        "apk": str(apk_path),
        "output_dir": str(output_dir),
        "manifest_path": str(manifest_path),
        "report_path": str(report_path),
        "manifest": manifest_info,
        "archive": manifest_info.get("archive") or {},
        "component_summary": manifest_info.get("component_summary") or {},
        "component_interactions": manifest_info.get("component_interactions") or {},
        "signing": manifest_info.get("signing") or {},
        "string_analysis": manifest_info.get("string_analysis") or {},
        **pipeline,
    }
    write_json(report_path, report)
    return report



def decompile_apk(apk_path: pathlib.Path, output_dir: pathlib.Path, *, mode: str = "auto") -> pathlib.Path:
    decompile_apk_report(apk_path, output_dir, mode=mode)
    return output_dir



def extract_dex_headers(apk_path: pathlib.Path) -> list[dict[str, Any]]:
    core = lockknife_core
    if core is None:
        try:
            import lockknife.lockknife_core as imported_core
        except Exception as exc:
            raise ApkError("lockknife_core extension is not available") from exc
        core = imported_core
    return extract_dex_headers_impl(apk_path, lockknife_core_module=core)



__all__ = [

    "ANDROID_NS",

    "ANDROID_ATTR",

    "SUPPORTED_DECOMPILE_MODES",

    "TEXT_FILE_SUFFIXES",

    "ApkError",

    "parse_apk_manifest",

    "available_decompile_tools",

    "decompile_apk_report",

    "decompile_apk",

    "extract_dex_headers",

]
