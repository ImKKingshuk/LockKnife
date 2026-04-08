from __future__ import annotations

from typing import Any

from defusedxml.ElementTree import ParseError, fromstring

from lockknife.modules.apk._decompile_inspection import (
    _android_attr,
    _coerce_manifest_bool,
    _normalize_component_name,
)


def component_details(
    manifest_xml: str | None, package: str | None, *, target_sdk: Any = None
) -> dict[str, Any]:
    empty = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "deeplinks": [],
        "interaction_analysis": _interaction_payload(),
        "summary": _summary_payload(),
    }
    if not manifest_xml:
        return empty
    try:
        root = fromstring(manifest_xml)
    except ParseError:
        return empty

    application = root.find("application")
    target_sdk_int = _int_value(target_sdk)
    inventory: dict[str, Any] = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "deeplinks": [],
        "interaction_analysis": _interaction_payload(),
    }
    exported_total = 0
    browsable_total = 0
    weak_provider_total = 0
    implicit_export_total = 0
    unprotected_exported_total = 0
    protected_exported_total = 0
    auto_verify_total = 0
    provider_authority_total = 0
    provider_grant_uri_total = 0

    for bucket, tag in {
        "activities": "activity",
        "services": "service",
        "receivers": "receiver",
        "providers": "provider",
    }.items():
        for node in application.findall(tag) if application is not None else []:
            item = _component_payload(node, bucket, package, target_sdk_int)
            inventory[bucket].append(item)
            if item["exported"]:
                exported_total += 1
                if item["permission_protected"]:
                    protected_exported_total += 1
                else:
                    unprotected_exported_total += 1
            if item["export_inference"] != "explicit":
                implicit_export_total += 1
            browsable_total += item["browsable_deeplink_count"]
            auto_verify_total += item["auto_verify_count"]
            if bucket == "providers":
                provider_authority_total += len(item.get("authorities") or [])
                if item.get("grant_uri_permissions"):
                    provider_grant_uri_total += 1
                if item["exported"] and not item["permission_protected"]:
                    weak_provider_total += 1
            for deeplink in item.get("deeplinks") or []:
                inventory["deeplinks"].append(deeplink)

    interaction = _interaction_analysis(inventory)
    inventory["interaction_analysis"] = interaction

    inventory["summary"] = _summary_payload(
        exported_total=exported_total,
        browsable_deeplink_total=browsable_total,
        provider_weak_permission_total=weak_provider_total,
        implicit_export_total=implicit_export_total,
        unprotected_exported_total=unprotected_exported_total,
        permission_protected_exported_total=protected_exported_total,
        auto_verify_total=auto_verify_total,
        provider_authority_total=provider_authority_total,
        provider_grant_uri_total=provider_grant_uri_total,
        intent_filter_overlap_total=len(interaction["overlaps"]),
        component_permission_gap_total=len(interaction["permission_gaps"]),
        custom_scheme_total=len(interaction["custom_schemes"]),
        custom_scheme_overlap_total=len(interaction["custom_scheme_overlaps"]),
    )
    return inventory


def _component_payload(
    node: Any, bucket: str, package: str | None, target_sdk: int | None
) -> dict[str, Any]:
    filters, deeplinks, browsable_count, auto_verify_count = _intent_filter_payload(node, package)
    exported, export_inference = _component_export_state(node, bucket, filters, target_sdk)
    permission = _normalize_component_name(package, _android_attr(node, "permission"))
    read_permission = _normalize_component_name(package, _android_attr(node, "readPermission"))
    write_permission = _normalize_component_name(package, _android_attr(node, "writePermission"))
    authorities = (
        _split_authorities(_android_attr(node, "authorities")) if bucket == "providers" else []
    )
    permission_protected = _permission_protected(
        bucket, permission, read_permission, write_permission
    )
    risk_flags = []
    if exported and not permission_protected:
        risk_flags.append("exported-without-permission")
    if export_inference != "explicit":
        risk_flags.append(f"export-inferred:{export_inference}")
    if browsable_count:
        risk_flags.append("browsable-deeplink")
    if auto_verify_count:
        risk_flags.append("auto-verify")
    if bucket == "providers" and authorities:
        risk_flags.append("content-provider-authority")
        if _coerce_manifest_bool(_android_attr(node, "grantUriPermissions")):
            risk_flags.append("grant-uri-permissions")
    actions = sorted({action for item in filters for action in item.get("actions") or []})
    categories = sorted({category for item in filters for category in item.get("categories") or []})
    schemes = sorted(
        {
            str(data.get("scheme"))
            for item in filters
            for data in item.get("data") or []
            if data.get("scheme")
        }
    )
    hosts = sorted(
        {
            str(data.get("host"))
            for item in filters
            for data in item.get("data") or []
            if data.get("host")
        }
    )
    path_patterns = sorted(
        {
            str(data.get(key))
            for item in filters
            for data in item.get("data") or []
            for key in ("path", "pathPrefix", "pathPattern")
            if data.get(key)
        }
    )
    representative_uri = next(
        (str(item.get("uri")) for item in deeplinks if str(item.get("uri") or "").strip()),
        None,
    )
    return {
        "name": _normalize_component_name(package, _android_attr(node, "name")),
        "enabled": _coerce_manifest_bool(_android_attr(node, "enabled")),
        "exported": exported,
        "export_inference": export_inference,
        "permission": permission,
        "read_permission": read_permission,
        "write_permission": write_permission,
        "authorities": authorities,
        "grant_uri_permissions": bool(
            _coerce_manifest_bool(_android_attr(node, "grantUriPermissions"))
        ),
        "permission_protected": permission_protected,
        "intent_filters": filters,
        "actions": actions,
        "categories": categories,
        "schemes": schemes,
        "hosts": hosts,
        "path_patterns": path_patterns,
        "probe_uri": representative_uri,
        "deeplinks": deeplinks,
        "deeplink_count": len(deeplinks),
        "browsable_deeplink_count": browsable_count,
        "auto_verify_count": auto_verify_count,
        "risk_flags": risk_flags,
    }


def _intent_filter_payload(
    node: Any, package: str | None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, int]:
    filters: list[dict[str, Any]] = []
    deeplinks: list[dict[str, Any]] = []
    browsable_count = 0
    auto_verify_count = 0
    component_name = _normalize_component_name(package, _android_attr(node, "name"))
    for intent_filter in node.findall("intent-filter"):
        actions = sorted(
            {
                value
                for child in intent_filter.findall("action")
                if (value := _normalize_component_name(None, _android_attr(child, "name")))
            }
        )
        categories = sorted(
            {
                value
                for child in intent_filter.findall("category")
                if (value := _normalize_component_name(None, _android_attr(child, "name")))
            }
        )
        data_items: list[dict[str, str]] = []
        uris: list[str] = []
        browsable = "android.intent.category.BROWSABLE" in categories
        auto_verify = bool(_coerce_manifest_bool(_android_attr(intent_filter, "autoVerify")))
        for child in intent_filter.findall("data"):
            item = {
                key: value
                for key in [
                    "scheme",
                    "host",
                    "port",
                    "path",
                    "pathPrefix",
                    "pathPattern",
                    "mimeType",
                ]
                if (value := _android_attr(child, key))
            }
            if not item:
                continue
            data_items.append(item)
            uri = _deeplink_uri(item)
            if uri:
                uris.append(uri)
                deeplinks.append(
                    {
                        "component": component_name,
                        "uri": uri,
                        "actions": actions,
                        "categories": categories,
                        "browsable": browsable,
                        "auto_verify": auto_verify,
                        "data": item,
                    }
                )
        if browsable and uris:
            browsable_count += len(uris)
        if auto_verify and uris:
            auto_verify_count += len(uris)
        filters.append(
            {
                "actions": actions,
                "categories": categories,
                "data": data_items,
                "deeplink_uris": uris,
                "browsable": browsable,
                "auto_verify": auto_verify,
            }
        )
    return filters, deeplinks, browsable_count, auto_verify_count


def _component_export_state(
    node: Any,
    bucket: str,
    filters: list[dict[str, Any]],
    target_sdk: int | None,
) -> tuple[bool, str]:
    exported_raw = _coerce_manifest_bool(_android_attr(node, "exported"))
    if exported_raw is not None:
        return exported_raw, "explicit"
    if bucket == "providers":
        authorities = _split_authorities(_android_attr(node, "authorities"))
        if target_sdk is not None and target_sdk >= 17:
            return False, "provider-default-false"
        return bool(authorities), "provider-authorities"
    if filters:
        return True, "intent-filter"
    return False, "default-false"


def _permission_protected(
    bucket: str,
    permission: str | None,
    read_permission: str | None,
    write_permission: str | None,
) -> bool:
    if permission:
        return True
    if bucket == "providers" and (read_permission or write_permission):
        return True
    return False


def _deeplink_uri(item: dict[str, str]) -> str | None:
    scheme = item.get("scheme")
    host = item.get("host")
    if scheme and host:
        path = item.get("path") or item.get("pathPrefix") or ""
        return f"{scheme}://{host}{path}"
    if scheme:
        return f"{scheme}://"
    if host:
        return host
    return None


def _split_authorities(value: str | None) -> list[str]:
    if not value:
        return []
    return sorted({item.strip() for item in str(value).split(";") if item.strip()})


def _summary_payload(
    *,
    exported_total: int = 0,
    browsable_deeplink_total: int = 0,
    provider_weak_permission_total: int = 0,
    implicit_export_total: int = 0,
    unprotected_exported_total: int = 0,
    permission_protected_exported_total: int = 0,
    auto_verify_total: int = 0,
    provider_authority_total: int = 0,
    provider_grant_uri_total: int = 0,
    intent_filter_overlap_total: int = 0,
    component_permission_gap_total: int = 0,
    custom_scheme_total: int = 0,
    custom_scheme_overlap_total: int = 0,
) -> dict[str, int]:
    return {
        "exported_total": exported_total,
        "browsable_deeplink_total": browsable_deeplink_total,
        "provider_weak_permission_total": provider_weak_permission_total,
        "implicit_export_total": implicit_export_total,
        "unprotected_exported_total": unprotected_exported_total,
        "permission_protected_exported_total": permission_protected_exported_total,
        "auto_verify_total": auto_verify_total,
        "provider_authority_total": provider_authority_total,
        "provider_grant_uri_total": provider_grant_uri_total,
        "intent_filter_overlap_total": intent_filter_overlap_total,
        "component_permission_gap_total": component_permission_gap_total,
        "custom_scheme_total": custom_scheme_total,
        "custom_scheme_overlap_total": custom_scheme_overlap_total,
    }


def _interaction_payload() -> dict[str, Any]:
    return {
        "overlaps": [],
        "permission_gaps": [],
        "provider_authority_map": {},
        "custom_schemes": [],
        "custom_scheme_overlaps": [],
    }


def _interaction_analysis(inventory: dict[str, Any]) -> dict[str, Any]:
    scheme_host_map: dict[tuple[str, str], set[str]] = {}
    custom_scheme_map: dict[str, set[str]] = {}
    provider_authority_map: dict[str, set[str]] = {}
    permission_gaps: list[dict[str, Any]] = []
    sensitive_actions = {
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.PACKAGE_ADDED",
        "android.intent.action.PACKAGE_REPLACED",
        "android.intent.action.NEW_OUTGOING_CALL",
        "android.intent.action.SEND",
        "android.intent.action.SENDTO",
        "android.intent.action.VIEW",
        "android.intent.action.WEB_SEARCH",
    }
    custom_scheme_allowlist = {
        "http",
        "https",
        "content",
        "file",
        "geo",
        "mailto",
        "market",
        "sms",
        "smsto",
        "tel",
    }

    for bucket in ("activities", "services", "receivers", "providers"):
        for item in inventory.get(bucket) or []:
            name = str(item.get("name") or "")
            actions = [str(value) for value in item.get("actions") or []]
            schemes = [str(value) for value in item.get("schemes") or []]
            hosts = [str(value) for value in item.get("hosts") or []]
            for scheme in schemes:
                lowered = scheme.lower()
                if lowered not in custom_scheme_allowlist:
                    custom_scheme_map.setdefault(lowered, set()).add(name)
                if hosts:
                    for host in hosts:
                        scheme_host_map.setdefault((lowered, host.lower()), set()).add(name)
                else:
                    scheme_host_map.setdefault((lowered, ""), set()).add(name)
            if bucket == "providers":
                for authority in item.get("authorities") or []:
                    provider_authority_map.setdefault(str(authority).lower(), set()).add(name)
            if item.get("exported") and not item.get("permission_protected"):
                risky = sorted(set(actions).intersection(sensitive_actions))
                if bucket in {"activities", "services", "receivers"} and (
                    risky or schemes or hosts
                ):
                    permission_gaps.append(
                        {
                            "component": name,
                            "bucket": bucket,
                            "actions": actions,
                            "schemes": schemes,
                            "hosts": hosts,
                            "risk_flags": item.get("risk_flags") or [],
                            "reason": "exported component exposes intent filters or deep links without permission enforcement",
                        }
                    )

    overlaps: list[dict[str, Any]] = []
    for (scheme, host), names in sorted(scheme_host_map.items()):
        if len(names) < 2:
            continue
        overlap_type = (
            "custom-scheme"
            if scheme and scheme not in custom_scheme_allowlist
            else "deeplink-overlap"
        )
        overlaps.append(
            {
                "type": overlap_type,
                "scheme": scheme,
                "host": host or None,
                "components": sorted(names),
            }
        )

    custom_scheme_overlaps = [
        {"scheme": scheme, "components": sorted(names)}
        for scheme, names in sorted(custom_scheme_map.items())
        if len(names) > 1
    ]
    return {
        "overlaps": overlaps,
        "permission_gaps": permission_gaps,
        "provider_authority_map": {
            authority: sorted(names) for authority, names in sorted(provider_authority_map.items())
        },
        "custom_schemes": sorted(custom_scheme_map),
        "custom_scheme_overlaps": custom_scheme_overlaps,
    }


def _int_value(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except Exception:
        return None
