from __future__ import annotations



import hashlib

import pathlib

import zipfile

from typing import Any

from urllib.parse import urlparse

from defusedxml.ElementTree import ParseError, fromstring



from lockknife.modules.apk._decompile_shared import (
    ANDROID_ATTR,
    ASCII_STRING_RE,
    CERT_PIN_RE,
    HOST_HINT_RE,
    SECRET_INDICATOR_RE,
    TEXT_FILE_SUFFIXES,
    URL_RE,
)



def _android_attr(node: Any | None, name: str) -> str | None:
    if node is None:
        return None
    value = node.get(f"{ANDROID_ATTR}{name}") or node.get(f"android:{name}") or node.get(name)
    return str(value) if value is not None else None

def _coerce_manifest_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    raw = str(value).strip().lower()
    if raw in {"true", "1", "yes", "on"}:
        return True
    if raw in {"false", "0", "no", "off"}:
        return False
    return None

def _clean_strings(values: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out

def _apk_method(apk_obj: Any, method_name: str, default: Any = None) -> Any:
    method = getattr(apk_obj, method_name, None)
    if callable(method):
        try:
            return method()
        except TypeError:
            return default
    return default

def _normalize_component_name(package: str | None, name: str | None) -> str | None:
    if not name:
        return None
    text = str(name).strip()
    if not text:
        return None
    if text.startswith(".") and package:
        return f"{package}{text}"
    if "." not in text and package:
        return f"{package}.{text}"
    return text

def _intent_filter_payload(node: Any) -> tuple[list[dict[str, Any]], list[str], int]:
    filters: list[dict[str, Any]] = []
    deeplinks: list[str] = []
    browsable_count = 0
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
        for child in intent_filter.findall("data"):
            item = {
                key: value
                for key in ["scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType"]
                if (value := _android_attr(child, key))
            }
            if item:
                data_items.append(item)
                scheme = item.get("scheme")
                host = item.get("host")
                if scheme or host:
                    uri = f"{scheme or '*'}://{host or '*'}"
                    path_hint = item.get("path") or item.get("pathPrefix") or item.get("pathPattern")
                    if path_hint:
                        uri = f"{uri}{path_hint}"
                    deeplinks.append(uri)

        browsable = "android.intent.category.BROWSABLE" in categories
        if browsable:
            browsable_count += 1
        filters.append(
            {
                "actions": actions,
                "categories": categories,
                "data": data_items,
                "browsable": browsable,
            }
        )
    return filters, sorted(set(deeplinks)), browsable_count

def _component_details(manifest_xml: str | None, package: str | None) -> dict[str, Any]:
    if not manifest_xml:
        return {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "exported_total": 0,
            "browsable_deeplink_total": 0,
            "deeplinks": [],
        }

    try:
        root = fromstring(manifest_xml)
    except ParseError:
        return {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "exported_total": 0,
            "browsable_deeplink_total": 0,
            "deeplinks": [],
        }

    application = root.find("application")
    component_tags = {
        "activities": "activity",
        "services": "service",
        "receivers": "receiver",
        "providers": "provider",
    }
    inventory: dict[str, Any] = {key: [] for key in component_tags}
    exported_total = 0
    browsable_total = 0
    deeplinks: list[str] = []

    for key, tag in component_tags.items():
        for node in application.findall(tag) if application is not None else []:
            name = _normalize_component_name(package, _android_attr(node, "name"))
            intent_filters, component_deeplinks, browsable_count = _intent_filter_payload(node)
            raw_exported = _android_attr(node, "exported")
            inferred_exported = raw_exported is None and tag != "provider" and bool(intent_filters)
            exported = _coerce_manifest_bool(raw_exported)
            if exported is None:
                exported = inferred_exported if tag != "provider" else False
            item: dict[str, Any] = {
                "name": name,
                "exported": bool(exported),
                "exported_source": "manifest" if raw_exported is not None else "inferred",
                "permission": _android_attr(node, "permission"),
                "process": _android_attr(node, "process"),
                "enabled": _coerce_manifest_bool(_android_attr(node, "enabled")),
                "intent_filters": intent_filters,
                "deeplinks": component_deeplinks,
                "browsable": browsable_count > 0,
            }
            if tag == "provider":
                item.update(
                    {
                        "authorities": _android_attr(node, "authorities"),
                        "grant_uri_permissions": _coerce_manifest_bool(_android_attr(node, "grantUriPermissions")),
                        "read_permission": _android_attr(node, "readPermission"),
                        "write_permission": _android_attr(node, "writePermission"),
                    }
                )
            inventory[key].append(item)
            if item["exported"]:
                exported_total += 1
            browsable_total += browsable_count
            deeplinks.extend(component_deeplinks)

    summary = {
        "activities": len(inventory["activities"]),
        "services": len(inventory["services"]),
        "receivers": len(inventory["receivers"]),
        "providers": len(inventory["providers"]),
        "exported_activities": sum(1 for item in inventory["activities"] if item.get("exported")),
        "exported_services": sum(1 for item in inventory["services"] if item.get("exported")),
        "exported_receivers": sum(1 for item in inventory["receivers"] if item.get("exported")),
        "exported_providers": sum(1 for item in inventory["providers"] if item.get("exported")),
        "exported_total": exported_total,
        "browsable_deeplink_total": browsable_total,
        "provider_weak_permission_total": sum(
            1
            for item in inventory["providers"]
            if item.get("exported")
            and not item.get("read_permission")
            and not item.get("write_permission")
        ),
    }
    inventory["summary"] = summary
    inventory["exported_total"] = exported_total
    inventory["browsable_deeplink_total"] = browsable_total
    inventory["deeplinks"] = sorted(set(filter(None, deeplinks)))
    return inventory

def _archive_inventory(apk_path: pathlib.Path) -> dict[str, Any]:
    dex_files: list[str] = []
    native_libs: list[str] = []
    signer_files: list[str] = []
    asset_files = 0
    with zipfile.ZipFile(apk_path, "r") as archive:
        for name in archive.namelist():
            if name.endswith(".dex"):
                dex_files.append(name)
            elif name.startswith("lib/") and name.endswith(".so"):
                native_libs.append(name)
            elif name.startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC")):
                signer_files.append(name)
            elif name.startswith("assets/"):
                asset_files += 1
    return {
        "dex_files": dex_files,
        "dex_count": len(dex_files),
        "native_libraries": native_libs,
        "native_library_count": len(native_libs),
        "meta_inf_signers": signer_files,
        "asset_file_count": asset_files,
    }

def _string_preview(value: str, limit: int = 96) -> str:
    collapsed = " ".join(value.strip().split())
    if len(collapsed) <= limit:
        return collapsed
    return f"{collapsed[: limit - 3]}..."

def _redact_secret(value: str) -> str:
    preview = _string_preview(value, limit=80)
    if len(preview) <= 12:
        return preview
    return f"{preview[:6]}…{preview[-6:]}"

def _scan_archive_strings(apk_path: pathlib.Path) -> dict[str, Any]:
    urls: list[dict[str, str]] = []
    direct_hosts: list[dict[str, str]] = []
    secrets: list[dict[str, str]] = []
    pins: list[dict[str, str]] = []
    scanned_files: list[str] = []
    seen_urls: set[tuple[str, str]] = set()
    seen_hosts: set[tuple[str, str]] = set()
    seen_secrets: set[tuple[str, str]] = set()
    seen_pins: set[tuple[str, str]] = set()

    def candidate_names(names: list[str]) -> list[str]:
        def score(name: str) -> tuple[int, int, str]:
            path = pathlib.PurePosixPath(name)
            suffix = path.suffix.lower()
            priority = 5
            if name.startswith("assets/") or name.startswith("res/raw/"):
                priority = 0
            elif suffix in TEXT_FILE_SUFFIXES:
                priority = 1
            elif name.endswith(".dex"):
                priority = 2
            elif name.startswith("res/") or name.startswith("META-INF/"):
                priority = 3
            return (priority, len(name), name)

        return sorted(names, key=score)[:40]

    with zipfile.ZipFile(apk_path, "r") as archive:
        for name in candidate_names(archive.namelist()):
            try:
                data = archive.read(name)
            except (KeyError, OSError, RuntimeError, ValueError, zipfile.BadZipFile):
                continue
            if not data:
                continue
            scanned_files.append(name)
            sample = data[:1_000_000]
            suffix = pathlib.PurePosixPath(name).suffix.lower()
            if suffix in TEXT_FILE_SUFFIXES or name.endswith((".xml", ".json", ".properties")):
                text = sample.decode("utf-8", errors="ignore")
                candidates = [line for line in text.splitlines() if line.strip()]
            else:
                candidates = [match.decode("utf-8", errors="ignore") for match in ASCII_STRING_RE.findall(sample)]

            for candidate in candidates[:1000]:
                preview = _string_preview(candidate)
                for url in URL_RE.findall(candidate):
                    key = (name, url)
                    if key not in seen_urls:
                        seen_urls.add(key)
                        urls.append({"file": name, "value": url})
                    host = urlparse(url).hostname
                    if host and (name, host) not in seen_hosts:
                        seen_hosts.add((name, host))
                        direct_hosts.append({"file": name, "value": host})

                for host in HOST_HINT_RE.findall(candidate):
                    key = (name, host)
                    if key not in seen_hosts:
                        seen_hosts.add(key)
                        direct_hosts.append({"file": name, "value": host})

                if SECRET_INDICATOR_RE.search(candidate):
                    key = (name, preview)
                    if key not in seen_secrets:
                        seen_secrets.add(key)
                        secrets.append({"file": name, "preview": _redact_secret(candidate)})

                if CERT_PIN_RE.search(candidate):
                    key = (name, preview)
                    if key not in seen_pins:
                        seen_pins.add(key)
                        pins.append({"file": name, "preview": preview})

    return {
        "stats": {
            "files_scanned": len(scanned_files),
            "url_count": len(urls),
            "host_count": len(direct_hosts),
            "secret_indicator_count": len(secrets),
            "certificate_pin_indicator_count": len(pins),
        },
        "scanned_files": scanned_files,
        "urls": urls[:25],
        "hosts": direct_hosts[:25],
        "hardcoded_secret_indicators": secrets[:25],
        "certificate_pin_indicators": pins[:25],
    }

def _certificate_payload(cert: Any) -> dict[str, Any]:
    raw: bytes | None = None
    dump = getattr(cert, "dump", None)
    if callable(dump):
        try:
            raw = dump()
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            raw = None

    subject = str(getattr(cert, "subject", "") or "").strip() or None
    issuer = str(getattr(cert, "issuer", "") or "").strip() or None
    serial = getattr(cert, "serial_number", None)
    signature_algorithm = getattr(cert, "signature_algorithm", None)
    signature_algorithm = getattr(signature_algorithm, "native", signature_algorithm)
    text_blob = " ".join(filter(None, [subject or "", issuer or ""])).lower()
    debugish = any(token in text_blob for token in ["android debug", "androiddebugkey", "testkey", "devkey"])
    payload = {
        "subject": subject,
        "issuer": issuer,
        "serial_number": str(serial) if serial is not None else None,
        "signature_algorithm": str(signature_algorithm) if signature_algorithm else None,
        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
        "is_debug_or_test": debugish,
    }
    return payload

def _signing_summary(apk_obj: Any, apk_path: pathlib.Path) -> dict[str, Any]:
    certificates = [_certificate_payload(cert) for cert in (_apk_method(apk_obj, "get_certificates", []) or [])]
    inventory = _archive_inventory(apk_path)
    signing = {
        "schemes": {
            "v1": bool(_apk_method(apk_obj, "is_signed_v1", False)),
            "v2": bool(_apk_method(apk_obj, "is_signed_v2", False)),
            "v3": bool(_apk_method(apk_obj, "is_signed_v3", False)),
        },
        "certificate_count": len(certificates),
        "certificates": certificates,
        "has_debug_or_test_certificate": any(cert.get("is_debug_or_test") for cert in certificates),
        "meta_inf_signers": inventory.get("meta_inf_signers") or [],
    }
    if not certificates and inventory.get("meta_inf_signers"):
        signing["has_debug_or_test_certificate"] = any(
            any(token in signer.lower() for token in ["test", "debug", "devkey"])
            for signer in inventory["meta_inf_signers"]
        )
    return signing
