from __future__ import annotations

import dataclasses
import json
import pathlib
import re
from typing import Any, cast

import click

from lockknife.core.case import case_output_path, register_case_artifact
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.cli_types import ANDROID_PACKAGE, READABLE_FILE
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules.security.attack_surface import assess_attack_surface
from lockknife.modules.security.bootloader import analyze_bootloader
from lockknife.modules.security.device_audit import run_device_audit
from lockknife.modules.security.hardware import analyze_hardware_security
from lockknife.modules.security.malware import scan_with_patterns, scan_with_yara
from lockknife.modules.security.network_scan import scan_network
from lockknife.modules.security.owasp import mastg_summary
from lockknife.modules.security.selinux import get_selinux_status


@click.group(help="Security assessment utilities.", cls=LockKnifeGroup)
def security() -> None:
    pass


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "security"


def _resolve_case_output(
    output: pathlib.Path | None, case_dir: pathlib.Path | None, *, filename: str
) -> tuple[pathlib.Path | None, bool]:
    if output is not None:
        return output, False
    if case_dir is None:
        return None, False
    return case_output_path(case_dir, area="derived", filename=filename), True


def _register_security_output(
    *,
    case_dir: pathlib.Path | None,
    path: pathlib.Path,
    category: str,
    source_command: str,
    serial: str | None = None,
    input_paths: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    if case_dir is None:
        return
    register_case_artifact(
        case_dir=case_dir,
        path=path,
        category=category,
        source_command=source_command,
        device_serial=serial,
        input_paths=input_paths,
        metadata=metadata,
    )


def _object_dict(value: object) -> dict[str, object]:
    return cast(dict[str, object], value) if isinstance(value, dict) else {}


def _object_list(value: object) -> list[object]:
    return cast(list[object], value) if isinstance(value, list) else []


@security.command("scan")
@click.option("-s", "--serial", required=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def scan_cmd(
    app: Any, serial: str, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    findings = run_device_audit(app.devices, serial)
    payload = [dataclasses.asdict(f) for f in findings]
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"security_scan_{_safe_name(serial)}.json"
    )
    if output:
        write_json(output, payload)
        _register_security_output(
            case_dir=case_dir,
            path=output,
            category="security-scan",
            source_command="security scan",
            serial=serial,
            metadata={"finding_count": len(payload)},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@security.command("selinux")
@click.option("-s", "--serial", required=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def selinux_cmd(
    app: Any, serial: str, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    status = get_selinux_status(app.devices, serial)
    payload = dataclasses.asdict(status)
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"security_selinux_{_safe_name(serial)}.json"
    )
    if output:
        write_json(output, payload)
        _register_security_output(
            case_dir=case_dir,
            path=output,
            category="security-selinux",
            source_command="security selinux",
            serial=serial,
            metadata={
                "status": payload.get("status") or payload.get("mode"),
                "risk_level": (
                    (payload.get("posture") if isinstance(payload.get("posture"), dict) else {})
                    or {}
                ).get("risk_level"),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@security.command("malware")
@click.option("--yara", "yara_rule", type=READABLE_FILE)
@click.option("--pattern", "patterns", multiple=True)
@click.option("--target", type=READABLE_FILE, required=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def malware_cmd(
    yara_rule: pathlib.Path | None,
    patterns: tuple[str, ...],
    target: pathlib.Path,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    if yara_rule:
        matches = [dataclasses.asdict(m) for m in scan_with_yara(yara_rule, target)]
        payload = {"engine": "yara", "matches": matches}
    else:
        payload = {"engine": "patterns", "matches": scan_with_patterns(list(patterns), target)}
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"security_malware_{_safe_name(target.stem)}.json"
    )
    if output:
        write_json(output, payload)
        input_paths = [str(target)] + ([str(yara_rule)] if yara_rule is not None else [])
        _register_security_output(
            case_dir=case_dir,
            path=output,
            category="security-malware",
            source_command="security malware",
            input_paths=input_paths,
            metadata={
                "engine": payload["engine"],
                "pattern_count": len(patterns),
                "match_count": len(payload["matches"]),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@security.command("network-scan")
@click.option("-s", "--serial", required=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def network_scan_cmd(
    app: Any, serial: str, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    scan = scan_network(app.devices, serial)
    payload: dict[str, Any] = {
        "dns": scan.dns,
        "dns_cache": scan.dns_cache,
        "listening": [dataclasses.asdict(p) for p in scan.listening],
        "raw": scan.raw,
    }
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"security_network_scan_{_safe_name(serial)}.json"
    )
    if output:
        write_json(output, payload)
        _register_security_output(
            case_dir=case_dir,
            path=output,
            category="security-network-scan",
            source_command="security network-scan",
            serial=serial,
            metadata={
                "listening_count": len(payload["listening"]),
                "dns_count": len(payload["dns"]),
                "dns_cache_count": len(payload["dns_cache"]),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@security.command("bootloader")
@click.option("-s", "--serial", required=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def bootloader_cmd(
    app: Any, serial: str, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    status = dataclasses.asdict(analyze_bootloader(app.devices, serial))
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"security_bootloader_{_safe_name(serial)}.json"
    )
    if output:
        write_json(output, status)
        _register_security_output(
            case_dir=case_dir,
            path=output,
            category="security-bootloader",
            source_command="security bootloader",
            serial=serial,
            metadata={"unlocked": status.get("unlocked")},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(status))


@security.command("hardware")
@click.option("-s", "--serial", required=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def hardware_cmd(
    app: Any, serial: str, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    status = dataclasses.asdict(analyze_hardware_security(app.devices, serial))
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"security_hardware_{_safe_name(serial)}.json"
    )
    if output:
        write_json(output, status)
        _register_security_output(
            case_dir=case_dir,
            path=output,
            category="security-hardware",
            source_command="security hardware",
            serial=serial,
            metadata={"tee_present": status.get("tee_present")},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(status))


@security.command("attack-surface")
@click.option("--package", type=ANDROID_PACKAGE)
@click.option("--serial")
@click.option("--apk", type=READABLE_FILE)
@click.option("--artifacts", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def attack_surface_cmd(
    app: Any,
    package: str | None,
    serial: str | None,
    apk: pathlib.Path | None,
    artifacts: pathlib.Path | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    if not any((package, apk, artifacts)):
        raise click.UsageError("Provide at least one of --package, --apk, or --artifacts")
    report: dict[str, Any] = assess_attack_surface(
        app.devices, package=package, serial=serial, apk_path=apk, artifacts_path=artifacts
    )
    name_hint = (
        report.get("package")
        or (artifacts.stem if artifacts is not None else None)
        or (apk.stem if apk is not None else None)
        or "attack_surface"
    )
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"security_attack_surface_{_safe_name(str(name_hint))}.json"
    )
    if output:
        write_json(output, report)
        _register_security_output(
            case_dir=case_dir,
            path=output,
            category="security-attack-surface",
            source_command="security attack-surface",
            serial=serial,
            input_paths=[str(path) for path in (apk, artifacts) if path is not None],
            metadata={
                "package": report.get("package"),
                "finding_count": len(_object_list(report.get("findings"))),
                "live_probe_enabled": bool(
                    _object_dict(report.get("probe_results")).get("attempted")
                ),
                "risk_level": _object_dict(report.get("risk_summary")).get("level"),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(report))


@security.command("owasp")
@click.option("--artifacts", type=click.Path(dir_okay=False, path_type=pathlib.Path), required=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def owasp_cmd(
    artifacts: pathlib.Path, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    data = json.loads(artifacts.read_text(encoding="utf-8"))
    payload = mastg_summary(data)
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"security_owasp_{_safe_name(artifacts.stem)}.json"
    )
    if output:
        write_json(output, payload)
        _register_security_output(
            case_dir=case_dir,
            path=output,
            category="security-owasp",
            source_command="security owasp",
            input_paths=[str(artifacts)],
            metadata={
                "artifact_source": str(artifacts),
                "mastg_total": len(payload.get("mastg_ids") or []),
                "owasp_total": len(payload.get("owasp_categories") or []),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))
