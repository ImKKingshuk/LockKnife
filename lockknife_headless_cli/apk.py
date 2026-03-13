from __future__ import annotations

import dataclasses
import json
import pathlib
import re
from typing import Any

import click

from lockknife.core.case import case_output_path, register_case_artifact
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.cli_types import ANDROID_PACKAGE, READABLE_FILE
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules.apk.device_pull import pull_apk_from_device
from lockknife.modules.apk.decompile import decompile_apk_report, extract_dex_headers, parse_apk_manifest
from lockknife.modules.apk.permissions import score_permissions
from lockknife.modules.apk.static_analysis import analyze_apk
from lockknife.modules.apk.vulnerability import vulnerability_report
from lockknife.modules.security.malware import scan_with_yara


@click.group(help="APK analysis: manifest parsing, permission scoring, static checks.", cls=LockKnifeGroup)
def apk() -> None:
    pass


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "artifact"


def _resolve_case_output(output: pathlib.Path | None, case_dir: pathlib.Path | None, *, filename: str) -> tuple[pathlib.Path | None, bool]:
    if output is not None:
        return output, False
    if case_dir is None:
        return None, False
    return case_output_path(case_dir, area="derived", filename=filename), True


def _register_apk_output(
    *,
    case_dir: pathlib.Path | None,
    output: pathlib.Path,
    category: str,
    source_command: str,
    input_paths: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    if case_dir is None:
        return
    register_case_artifact(
        case_dir=case_dir,
        path=output,
        category=category,
        source_command=source_command,
        input_paths=input_paths,
        metadata=metadata,
    )


@apk.command("decompile")
@click.argument("apk_path", type=READABLE_FILE)
@click.option("--output", type=click.Path(file_okay=False, path_type=pathlib.Path))
@click.option(
    "--mode",
    type=click.Choice(["auto", "unpack", "apktool", "jadx", "hybrid"], case_sensitive=False),
    default="auto",
    show_default=True,
)
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def decompile_cmd(apk_path: pathlib.Path, output: pathlib.Path | None, mode: str, case_dir: pathlib.Path | None) -> None:
    if output is None:
        if case_dir is None:
            raise click.ClickException("Either --output or --case-dir is required")
        output = case_dir / "evidence" / f"apk_decompile_{_safe_name(apk_path.stem)}"
    report = decompile_apk_report(apk_path, output, mode=mode.lower())
    manifest_path = pathlib.Path(report["manifest_path"])
    report_path = pathlib.Path(report["report_path"])
    if case_dir is not None and manifest_path.exists():
        _register_apk_output(
            case_dir=case_dir,
            output=manifest_path,
            category="apk-decompile-manifest",
            source_command="apk decompile",
            input_paths=[str(apk_path)],
            metadata={"output_dir": str(output), "selected_mode": report.get("selected_mode")},
        )
    if case_dir is not None and report_path.exists():
        _register_apk_output(
            case_dir=case_dir,
            output=report_path,
            category="apk-decompile-report",
            source_command="apk decompile",
            input_paths=[str(apk_path)],
            metadata={"output_dir": str(output), "selected_mode": report.get("selected_mode")},
        )
    console.print(str(output))


@apk.command("permissions")
@click.argument("apk_path", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def permissions_cmd(apk_path: pathlib.Path, output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
    info = parse_apk_manifest(apk_path)
    total, risks = score_permissions(list(info.get("permissions") or []))
    payload = {"package": info.get("package"), "score": total, "risks": [dataclasses.asdict(r) for r in risks]}
    output, derived = _resolve_case_output(output, case_dir, filename=f"apk_permissions_{_safe_name(apk_path.stem)}.json")
    if output:
        write_json(output, payload)
        _register_apk_output(
            case_dir=case_dir,
            output=output,
            category="apk-permissions",
            source_command="apk permissions",
            input_paths=[str(apk_path)],
            metadata={"package": info.get("package")},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@apk.command("analyze")
@click.argument("apk_path", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def analyze_cmd(apk_path: pathlib.Path, output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
    report = analyze_apk(apk_path)
    dex_headers = extract_dex_headers(apk_path)
    payload = {
        "package": report.package,
        "manifest": report.manifest,
        "findings": [dataclasses.asdict(f) for f in report.findings],
        "permission_risk": report.permission_risk,
        "risk_summary": report.risk_summary,
        "mastg": report.mastg,
        "dex_headers": dex_headers,
    }
    output, derived = _resolve_case_output(output, case_dir, filename=f"apk_analysis_{_safe_name(apk_path.stem)}.json")
    if output:
        write_json(output, payload)
        _register_apk_output(
            case_dir=case_dir,
            output=output,
            category="apk-analysis",
            source_command="apk analyze",
            input_paths=[str(apk_path)],
            metadata={
                "package": report.package,
                "finding_count": len(report.findings),
                "dex_header_count": len(dex_headers),
                "risk_score": report.risk_summary.get("score"),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@apk.command("vulnerability")
@click.argument("apk_path", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def vuln_cmd(apk_path: pathlib.Path, output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
    rep = vulnerability_report(apk_path)
    payload = {
        "package": rep.package,
        "version_name": rep.version_name,
        "version_code": rep.version_code,
        "manifest_flags": rep.manifest_flags,
        "components": rep.components,
        "uses_libraries": rep.uses_libraries,
        "findings": rep.findings,
        "permission_risk": rep.permission_risk,
        "risk_summary": rep.risk_summary,
        "mastg": rep.mastg,
        "cve": rep.cve,
        "cve_by_component": rep.cve_by_component,
        "cve_summary": rep.cve_summary,
        "string_analysis": rep.string_analysis,
        "signing": rep.signing,
    }
    output, derived = _resolve_case_output(output, case_dir, filename=f"apk_vulnerability_{_safe_name(apk_path.stem)}.json")
    if output:
        write_json(output, payload)
        _register_apk_output(
            case_dir=case_dir,
            output=output,
            category="apk-vulnerability",
            source_command="apk vulnerability",
            input_paths=[str(apk_path)],
            metadata={
                "package": rep.package,
                "cve_count": rep.cve_summary.get("cve_count"),
                "risk_score": rep.risk_summary.get("score"),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@apk.command("scan")
@click.option("--yara", "yara_rule", type=READABLE_FILE, required=True)
@click.option("-s", "--serial")
@click.option("--target", "package_name", type=ANDROID_PACKAGE)
@click.option("--apk", "apk_path", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def scan_cmd(
    app: Any,
    yara_rule: pathlib.Path,
    serial: str | None,
    package_name: str | None,
    apk_path: pathlib.Path | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    if apk_path is None and not package_name:
        raise click.ClickException("Provide --apk or --target")
    if apk_path is None and not serial:
        raise click.ClickException("Provide --serial when using --target")

    local_apk = apk_path
    if local_apk is None and serial and package_name:
        local_apk = pull_apk_from_device(app.devices, serial, package_name)
    if local_apk is None:
        raise click.ClickException("Unable to resolve APK path")

    matches = [dataclasses.asdict(m) for m in scan_with_yara(yara_rule, local_apk)]
    payload = {"apk": str(local_apk), "package": package_name, "engine": "yara", "matches": matches}
    stem = package_name or (local_apk.stem if local_apk is not None else "scan")
    output, derived = _resolve_case_output(output, case_dir, filename=f"apk_scan_{_safe_name(stem)}.json")
    if output:
        write_json(output, payload)
        _register_apk_output(
            case_dir=case_dir,
            output=output,
            category="apk-scan",
            source_command="apk scan",
            input_paths=[str(apk_path)] if apk_path is not None else None,
            metadata={"package": package_name, "serial": serial, "match_count": len(matches)},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))
