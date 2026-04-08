from __future__ import annotations

import pathlib
from typing import Any

from lockknife.core.device import DeviceManager
from lockknife.modules.security._attack_surface_live import probe_findings, probe_surface
from lockknife.modules.security._attack_surface_score import risk_summary
from lockknife.modules.security._attack_surface_static import (
    load_static_source,
    static_findings,
    surface_inventory,
)
from lockknife.modules.security.owasp import mastg_summary


def assess_attack_surface_report(
    devices: DeviceManager | None,
    *,
    package: str | None = None,
    serial: str | None = None,
    apk_path: pathlib.Path | None = None,
    artifacts_path: pathlib.Path | None = None,
) -> dict[str, Any]:
    if not any((package, apk_path, artifacts_path)):
        raise ValueError("Provide at least one of package, apk_path, or artifacts_path")

    static_source = load_static_source(apk_path=apk_path, artifacts_path=artifacts_path)
    manifest = static_source["manifest"]
    package_name = package or static_source.get("package")
    if serial and not package_name:
        raise ValueError("Package name is required for live device probes")

    static_analysis = surface_inventory(manifest, package_name)
    findings = static_findings(manifest)
    live_analysis = probe_surface(
        devices,
        serial=serial,
        package=package_name,
        deeplinks=static_analysis["browsable_deeplinks"],
        providers=static_analysis["weak_providers"],
        exported_components=static_analysis["exported_components"],
    )
    findings.extend(probe_findings(live_analysis))
    risk = risk_summary(findings, static_analysis=static_analysis, live_analysis=live_analysis)
    mastg = mastg_summary({"findings": findings, "risk_summary": risk})

    return {
        "package": package_name,
        "manifest": manifest,
        "surface": static_analysis,
        "static_analysis": static_analysis,
        "probe_results": live_analysis,
        "live_analysis": live_analysis,
        "findings": findings,
        "risk_summary": risk,
        "mastg": mastg,
        "review_guide": {
            "static": static_analysis.get("review_queue") or [],
            "live": live_analysis.get("review_queue") or [],
            "next_steps": risk.get("next_steps") or [],
        },
        "assessment_scope": {
            "source_kind": static_source["source_kind"],
            "static": manifest is not None,
            "live": live_analysis["attempted"],
        },
        "inputs": {
            "package": package_name,
            "serial": serial,
            "apk_path": str(apk_path) if apk_path is not None else None,
            "artifacts_path": str(artifacts_path) if artifacts_path is not None else None,
        },
    }
