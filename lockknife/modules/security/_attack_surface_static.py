from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

from lockknife.modules.apk.decompile import parse_apk_manifest
from lockknife.modules.apk.static_analysis import findings_from_manifest
from lockknife.modules.security._deeplink_probe import deeplink_review_notes, deeplink_uri
from lockknife.modules.security._provider_probe import provider_review_notes

ATTACK_SURFACE_FINDING_IDS = {
    "exported_components",
    "browsable_deeplinks",
    "weak_exported_provider",
    "component_permission_gap",
    "intent_filter_overlap",
    "custom_scheme_collision",
}


def load_static_source(
    *, apk_path: pathlib.Path | None, artifacts_path: pathlib.Path | None
) -> dict[str, Any]:
    artifact_payload: dict[str, Any] | None = None
    manifest: dict[str, Any] | None = None
    source_kind = "package"

    if artifacts_path is not None:
        artifact_payload = json.loads(artifacts_path.read_text(encoding="utf-8"))
        manifest = extract_manifest(artifact_payload)
        source_kind = "artifacts"
    if manifest is None and apk_path is not None:
        manifest = parse_apk_manifest(apk_path)
        source_kind = "apk"

    package = extract_package(artifact_payload, manifest)
    return {
        "artifact_payload": artifact_payload,
        "manifest": manifest,
        "package": package,
        "source_kind": source_kind,
    }


def extract_manifest(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    manifest = payload.get("manifest")
    if isinstance(manifest, dict):
        return manifest
    if any(key in payload for key in ("components", "component_summary", "deeplinks", "package")):
        return payload
    return None


def extract_package(payload: Any, manifest: dict[str, Any] | None) -> str | None:
    if isinstance(payload, dict):
        value = payload.get("package")
        if isinstance(value, str) and value.strip():
            return value.strip()
    if isinstance(manifest, dict):
        value = manifest.get("package")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def surface_inventory(manifest: dict[str, Any] | None, package: str | None) -> dict[str, Any]:
    components_root = manifest.get("components") if isinstance(manifest, dict) else None
    interactions_root = (
        manifest.get("component_interactions") if isinstance(manifest, dict) else None
    )
    component_summary = None
    if isinstance(manifest, dict):
        component_summary = manifest.get("component_summary")
    if not isinstance(component_summary, dict) and isinstance(components_root, dict):
        component_summary = components_root.get("summary")
    if not isinstance(interactions_root, dict) and isinstance(components_root, dict):
        interactions_root = components_root.get("interaction_analysis")
    if not isinstance(interactions_root, dict):
        interactions_root = {}
    permission_gap_names = {
        str(item.get("component") or "").strip()
        for item in interactions_root.get("permission_gaps") or []
        if isinstance(item, dict) and str(item.get("component") or "").strip()
    }

    exported_components: list[dict[str, Any]] = []
    browsable_deeplinks: list[dict[str, Any]] = []
    weak_providers: list[dict[str, Any]] = []
    component_clusters: dict[str, list[dict[str, Any]]] = {
        "activity": [],
        "service": [],
        "receiver": [],
        "provider": [],
    }
    if isinstance(components_root, dict):
        for component_type in ("activities", "services", "receivers", "providers"):
            normalized_type = (
                component_type[:-1] if component_type.endswith("s") else component_type
            )
            for component in components_root.get(component_type, []) or []:
                if not isinstance(component, dict) or not component.get("exported"):
                    continue
                risk_flags = [
                    str(flag) for flag in component.get("risk_flags") or [] if isinstance(flag, str)
                ]
                entry = {
                    "type": normalized_type,
                    "name": component.get("name"),
                    "permission": component.get("permission"),
                    "permission_protected": bool(component.get("permission_protected")),
                    "export_inference": component.get("export_inference"),
                    "risk_flags": risk_flags,
                    "actions": list(component.get("actions") or []),
                    "schemes": list(component.get("schemes") or []),
                    "hosts": list(component.get("hosts") or []),
                    "probe_uri": component.get("probe_uri"),
                    "deeplink_count": int(component.get("deeplink_count") or 0),
                    "browsable_deeplink_count": int(component.get("browsable_deeplink_count") or 0),
                    "auto_verify_count": int(component.get("auto_verify_count") or 0),
                    "review_notes": _component_review_notes(normalized_type, component),
                    "static_permission_gap": str(component.get("name") or "")
                    in permission_gap_names,
                }
                if normalized_type == "provider":
                    entry["authorities"] = list(component.get("authorities") or [])
                    entry["read_permission"] = component.get("read_permission")
                    entry["write_permission"] = component.get("write_permission")
                    entry["grant_uri_permissions"] = bool(component.get("grant_uri_permissions"))
                exported_components.append(entry)
                component_clusters.setdefault(normalized_type, []).append(entry)
                if normalized_type == "provider" and not component.get("permission_protected"):
                    weak_providers.append(entry)
        for deeplink in components_root.get("deeplinks", []) or []:
            if not isinstance(deeplink, dict):
                continue
            browsable_deeplinks.append(
                {
                    **deeplink,
                    "uri": deeplink_uri(deeplink),
                    "review_notes": deeplink_review_notes(deeplink),
                }
            )

    exported_total = int(
        (component_summary or {}).get("exported_total") or len(exported_components)
    )
    summary = {
        "package": package,
        "exported_total": exported_total,
        "activity_exported_total": len(component_clusters.get("activity") or []),
        "service_exported_total": len(component_clusters.get("service") or []),
        "receiver_exported_total": len(component_clusters.get("receiver") or []),
        "provider_exported_total": len(component_clusters.get("provider") or []),
        "browsable_deeplink_total": int(
            (component_summary or {}).get("browsable_deeplink_total") or len(browsable_deeplinks)
        ),
        "provider_weak_permission_total": int(
            (component_summary or {}).get("provider_weak_permission_total") or len(weak_providers)
        ),
        "implicit_export_total": int((component_summary or {}).get("implicit_export_total") or 0),
        "unprotected_exported_total": int(
            (component_summary or {}).get("unprotected_exported_total") or 0
        ),
        "permission_protected_exported_total": int(
            (component_summary or {}).get("permission_protected_exported_total") or 0
        ),
        "auto_verify_total": int((component_summary or {}).get("auto_verify_total") or 0),
        "provider_authority_total": int(
            (component_summary or {}).get("provider_authority_total") or 0
        ),
        "provider_grant_uri_total": int(
            (component_summary or {}).get("provider_grant_uri_total") or 0
        ),
        "custom_scheme_total": sum(
            1
            for item in browsable_deeplinks
            if not str(item.get("uri") or "").startswith(("http://", "https://"))
        ),
        "web_link_total": sum(
            1
            for item in browsable_deeplinks
            if str(item.get("uri") or "").startswith(("http://", "https://"))
        ),
        "component_permission_gap_total": int(
            (component_summary or {}).get("component_permission_gap_total")
            or len(interactions_root.get("permission_gaps") or [])
        ),
        "intent_filter_overlap_total": int(
            (component_summary or {}).get("intent_filter_overlap_total")
            or len(interactions_root.get("overlaps") or [])
        ),
        "custom_scheme_overlap_total": int(
            (component_summary or {}).get("custom_scheme_overlap_total")
            or len(interactions_root.get("custom_scheme_overlaps") or [])
        ),
    }
    return {
        "summary": summary,
        "exported_components": exported_components,
        "browsable_deeplinks": browsable_deeplinks,
        "weak_providers": weak_providers,
        "component_clusters": component_clusters,
        "interactions": interactions_root,
        "review_queue": _review_queue(
            exported_components, browsable_deeplinks, weak_providers, interactions_root
        ),
    }


def static_findings(manifest: dict[str, Any] | None) -> list[dict[str, Any]]:
    if manifest is None:
        return []
    normalized = dict(manifest)
    components = (
        normalized.get("components") if isinstance(normalized.get("components"), dict) else {}
    )
    if "component_summary" not in normalized and isinstance(components, dict):
        summary = components.get("summary")
        if isinstance(summary, dict):
            normalized["component_summary"] = summary
    if "deeplinks" not in normalized and isinstance(components, dict):
        deeplinks = components.get("deeplinks")
        if isinstance(deeplinks, list):
            normalized["deeplinks"] = deeplinks
    findings: list[dict[str, Any]] = []
    for finding in findings_from_manifest(normalized):
        if finding.id not in ATTACK_SURFACE_FINDING_IDS:
            continue
        payload = dataclasses.asdict(finding)
        payload.setdefault("evidence", _evidence_for_finding(payload))
        findings.append(payload)
    return findings


def _component_review_notes(component_type: str, component: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    if not component.get("permission_protected"):
        notes.append("Exported without permission guard")
    if component.get("export_inference") and component.get("export_inference") != "explicit":
        notes.append(f"Export inferred via {component.get('export_inference')}")
    if component.get("browsable_deeplink_count"):
        notes.append("Browsable deep-link entry point")
    if component.get("actions"):
        notes.append("Intent filters present; verify caller trust and permission gating")
    if component_type == "provider":
        notes.extend(provider_review_notes(component))
    return notes


def _review_queue(
    exported_components: list[dict[str, Any]],
    browsable_deeplinks: list[dict[str, Any]],
    weak_providers: list[dict[str, Any]],
    interactions: dict[str, Any],
) -> list[str]:
    queue: list[str] = []
    for provider in weak_providers[:3]:
        queue.append(
            f"Inspect exported provider {provider.get('name')} for readable authorities and URI grants."
        )
    for deeplink in browsable_deeplinks[:2]:
        queue.append(
            f"Exercise deep link {deeplink.get('uri')} and review auth/session assumptions."
        )
    for component in exported_components[:2]:
        if component.get("type") != "provider":
            queue.append(
                f"Review exported {component.get('type')} {component.get('name')} for unintended external entry."
            )
    for gap in (interactions.get("permission_gaps") or [])[:2]:
        queue.append(
            f"Validate permission enforcement for {gap.get('component')} because exported intent or deep-link surface lacks an explicit guard."
        )
    for overlap in (interactions.get("overlaps") or [])[:2]:
        queue.append(
            f"Review routing overlap for scheme {overlap.get('scheme')} across components {', '.join(overlap.get('components') or [])}."
        )
    return queue[:6]


def _evidence_for_finding(finding: dict[str, Any]) -> list[str]:
    details_obj = finding.get("details")
    details = details_obj if isinstance(details_obj, dict) else {}
    if isinstance(finding.get("evidence"), list):
        return [str(item) for item in finding["evidence"][:5]]
    for key in ("providers", "deeplinks"):
        values = details.get(key)
        if isinstance(values, list):
            return [str(item) for item in values[:5]]
    summary = details.get("summary")
    if isinstance(summary, dict):
        return [f"{key}={value}" for key, value in list(summary.items())[:4]]
    return []
