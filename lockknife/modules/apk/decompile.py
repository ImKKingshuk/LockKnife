from __future__ import annotations

import pathlib
import zipfile
from typing import Any

from defusedxml.ElementTree import ParseError, fromstring

from lockknife.core.serialize import write_json
from lockknife.modules.apk._code_signals import scan_archive_code_signals
from lockknife.modules.apk._decompile_archive import archive_inventory
from lockknife.modules.apk._decompile_dex import extract_dex_headers_impl
from lockknife.modules.apk._decompile_inspection import (
    _android_attr,
    _apk_method,
    _clean_strings,
    _coerce_manifest_bool,
    _normalize_component_name,
)
from lockknife.modules.apk._decompile_shared import (
    ANDROID_ATTR,
    ANDROID_NS,
    SUPPORTED_DECOMPILE_MODES,
    TEXT_FILE_SUFFIXES,
    ApkError,
    _require_androguard,
)
from lockknife.modules.apk._decompile_tools import available_decompile_tools, run_decompile_pipeline
from lockknife.modules.apk._manifest_components import component_details
from lockknife.modules.apk._signing import signing_summary

lockknife_core = None


def _parse_apk_manifest_native(apk_path: pathlib.Path) -> dict[str, Any]:
    from lockknife.modules.apk._axml_parser import extract_manifest_xml_from_apk

    try:
        manifest_xml = extract_manifest_xml_from_apk(apk_path)
        root = fromstring(manifest_xml)
    except (OSError, ValueError, zipfile.BadZipFile, ParseError) as exc:
        raise ApkError(f"Unable to parse APK manifest: {exc}") from exc
    if root.tag != "manifest":
        raise ApkError("APK XML root must be manifest")

    package = root.get("package")
    version_code = _android_attr(root, "versionCode")
    version_name = _android_attr(root, "versionName")

    sdk_node = root.find("uses-sdk")
    min_sdk = _android_attr(sdk_node, "minSdkVersion")
    target_sdk = _android_attr(sdk_node, "targetSdkVersion")
    max_sdk = _android_attr(sdk_node, "maxSdkVersion")

    permissions = sorted(
        set(
            _clean_strings(
                [
                    _android_attr(node, "name")
                    for node in root.findall("uses-permission")
                    + root.findall("uses-permission-sdk-23")
                ]
            )
        )
    )
    features = sorted(
        set(_clean_strings([_android_attr(node, "name") for node in root.findall("uses-feature")]))
    )

    app_node = root.find("application")
    app_name = _android_attr(app_node, "label")
    uses_libraries = sorted(
        set(
            _clean_strings(
                [
                    _android_attr(node, "name")
                    for node in (app_node.findall("uses-library") if app_node is not None else [])
                ]
            )
        )
    )

    main_activity = None
    activities: list[str] = []
    services: list[str] = []
    receivers: list[str] = []
    providers: list[str] = []

    if app_node is not None:
        for act in app_node.findall("activity") + app_node.findall("activity-alias"):
            name = _android_attr(act, "name")
            if name:
                norm = _normalize_component_name(package, name)
                if norm:
                    activities.append(norm)
                for inf in act.findall("intent-filter"):
                    has_main = any(
                        _android_attr(a, "name") == "android.intent.action.MAIN"
                        for a in inf.findall("action")
                    )
                    has_launcher = any(
                        _android_attr(c, "name")
                        in {
                            "android.intent.category.LAUNCHER",
                            "android.intent.category.INFO",
                        }
                        for c in inf.findall("category")
                    )
                    if has_main and has_launcher and not main_activity:
                        main_activity = norm

        for srv in app_node.findall("service"):
            name = _android_attr(srv, "name")
            if name:
                norm = _normalize_component_name(package, name)
                if norm:
                    services.append(norm)

        for rec in app_node.findall("receiver"):
            name = _android_attr(rec, "name")
            if name:
                norm = _normalize_component_name(package, name)
                if norm:
                    receivers.append(norm)

        for prv in app_node.findall("provider"):
            name = _android_attr(prv, "name")
            if name:
                norm = _normalize_component_name(package, name)
                if norm:
                    providers.append(norm)

    components = component_details(manifest_xml, package, target_sdk=target_sdk)
    archive = archive_inventory(apk_path)
    strings = scan_archive_code_signals(apk_path)
    signing = signing_summary(None, apk_path)
    deeplinks = [
        str(item.get("uri"))
        for item in components.get("deeplinks") or []
        if isinstance(item, dict) and str(item.get("uri") or "").strip()
    ]

    debuggable = (
        _coerce_manifest_bool(_android_attr(app_node, "debuggable"))
        if app_node is not None
        else False
    )
    allow_backup = (
        _coerce_manifest_bool(_android_attr(app_node, "allowBackup"))
        if app_node is not None
        else None
    )
    uses_cleartext = (
        _coerce_manifest_bool(_android_attr(app_node, "usesCleartextTraffic"))
        if app_node is not None
        else None
    )
    net_sec = _android_attr(app_node, "networkSecurityConfig") if app_node is not None else None
    backup_agent = _android_attr(app_node, "backupAgent") if app_node is not None else None

    info = {
        "package": package,
        "app_name": app_name,
        "main_activity": main_activity,
        "version_name": version_name,
        "version_code": version_code,
        "sdk": {
            "min": min_sdk,
            "target": target_sdk,
            "max": max_sdk,
        },
        "permissions": permissions,
        "permission_details": {},
        "features": features,
        "uses_libraries": uses_libraries,
        "activities": _clean_strings(activities),
        "services": _clean_strings(services),
        "receivers": _clean_strings(receivers),
        "providers": _clean_strings(providers),
        "components": components,
        "component_summary": components.get("summary") or {},
        "component_interactions": components.get("interaction_analysis") or {},
        "deeplinks": sorted(set(deeplinks)),
        "manifest_xml": manifest_xml,
        "debuggable": bool(debuggable),
        "allow_backup": allow_backup,
        "uses_cleartext_traffic": uses_cleartext,
        "network_security_config": net_sec,
        "backup_agent": backup_agent,
        "archive": archive,
        "string_analysis": strings,
        "code_signals": {
            "libraries": strings.get("libraries") or [],
            "trackers": strings.get("trackers") or [],
            "signals": strings.get("code_signals") or [],
        },
        "signing": signing,
        "manifest_flags": {
            "debuggable": bool(debuggable),
            "allow_backup": allow_backup,
            "uses_cleartext_traffic": uses_cleartext,
            "network_security_config": net_sec,
            "backup_agent": backup_agent,
        },
    }
    return info


def parse_apk_manifest(apk_path: pathlib.Path) -> dict[str, Any]:
    APK = _require_androguard(raise_on_missing=False)
    if APK is not None:
        try:
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
                "main_activity": _normalize_component_name(
                    package, _apk_method(apk_obj, "get_main_activity")
                ),
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
                "uses_libraries": sorted(
                    set(_clean_strings(_apk_method(apk_obj, "get_libraries", [])))
                ),
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
                    info["allow_backup"] = _coerce_manifest_bool(
                        _android_attr(app_node, "allowBackup")
                    )
                    info["uses_cleartext_traffic"] = _coerce_manifest_bool(
                        _android_attr(app_node, "usesCleartextTraffic")
                    )
                    info["network_security_config"] = _android_attr(
                        app_node, "networkSecurityConfig"
                    )
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
        except Exception:
            return _parse_apk_manifest_native(apk_path)

    return _parse_apk_manifest_native(apk_path)


def decompile_apk_report(
    apk_path: pathlib.Path, output_dir: pathlib.Path, *, mode: str = "auto", timeout_s: float = 300
) -> dict[str, Any]:
    if not apk_path.exists():
        raise ApkError(f"APK not found: {apk_path}")
    if output_dir.exists() and (not output_dir.is_dir() or any(output_dir.iterdir())):
        raise ApkError(f"Decompile output must be a new or empty directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_info = parse_apk_manifest(apk_path)
    manifest_path = output_dir / "manifest.json"
    write_json(manifest_path, manifest_info)
    pipeline = run_decompile_pipeline(
        apk_path, output_dir, requested_mode=mode, timeout_s=timeout_s
    )

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


def decompile_apk(
    apk_path: pathlib.Path, output_dir: pathlib.Path, *, mode: str = "auto", timeout_s: float = 300
) -> pathlib.Path:
    decompile_apk_report(apk_path, output_dir, mode=mode, timeout_s=timeout_s)
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
