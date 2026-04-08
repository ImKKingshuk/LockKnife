from __future__ import annotations

import dataclasses
import json
import pathlib
import re
from typing import cast

import click

from lockknife.core.case import case_output_path, register_case_artifact
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.cli_types import ANDROID_PACKAGE, DOMAIN, HASH_HEX, IPV4, READABLE_FILE
from lockknife.core.logging import get_logger
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules._case_enrichment_payloads import (
    cve_payload,
    ioc_payload,
    stix_payload,
    taxii_payload,
    virustotal_payload,
)
from lockknife.modules.intelligence.cve import (
    android_cve_risk_score,
    correlate_cves_for_apk_package,
    correlate_cves_for_kernel_version,
)
from lockknife.modules.intelligence.ioc import (
    detect_iocs,
    load_stix_indicators_from_url,
    load_taxii_indicators,
)
from lockknife.modules.intelligence.ioc_db import (
    IocRecord,
    add_iocs,
    list_iocs,
    load_feed_config,
    now,
    sync_ioc_feeds,
)
from lockknife.modules.intelligence.otx import OtxError, indicator_reputation
from lockknife.modules.intelligence.virustotal import (
    domain_report,
    file_report,
    ip_report,
    submit_url_for_analysis,
    url_report,
)

log = get_logger()


def _object_dict(value: object) -> dict[str, object]:
    return cast(dict[str, object], value) if isinstance(value, dict) else {}


def _score_value(data: dict[str, object]) -> int:
    score = data.get("score")
    if isinstance(score, bool):
        return int(score)
    if isinstance(score, int):
        return score
    if isinstance(score, float):
        return int(score)
    if isinstance(score, str):
        try:
            return int(score)
        except ValueError:
            return 0
    return 0


@click.group(help="Threat intelligence helpers (VT, IOC, CVE).", cls=LockKnifeGroup)
def intel() -> None:
    pass


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "intel"


def _resolve_case_output(
    output: pathlib.Path | None, case_dir: pathlib.Path | None, *, filename: str
) -> tuple[pathlib.Path | None, bool]:
    if output is not None:
        return output, False
    if case_dir is None:
        return None, False
    return case_output_path(case_dir, area="derived", filename=filename), True


def _register_intel_output(
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


@intel.command("virustotal")
@click.option("--hash", "file_hash", type=HASH_HEX)
@click.option("--url", "url_value")
@click.option("--domain", type=DOMAIN)
@click.option("--ip", "ip_address", type=IPV4)
@click.option("--submit-url")
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def vt_cmd(
    file_hash: str | None,
    url_value: str | None,
    domain: str | None,
    ip_address: str | None,
    submit_url: str | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    selected = [("file", file_hash), ("url", url_value), ("domain", domain), ("ip", ip_address)]
    populated = [(kind, value) for kind, value in selected if value]
    if submit_url:
        if populated:
            raise click.ClickException("Use --submit-url by itself")
        indicator_type, indicator = "url", submit_url
        report = submit_url_for_analysis(submit_url)
    else:
        if len(populated) != 1:
            raise click.ClickException("Provide exactly one of --hash, --url, --domain, or --ip")
        indicator_type, indicator = populated[0]
        if indicator_type == "file":
            report = file_report(str(indicator))
        elif indicator_type == "url":
            report = url_report(str(indicator))
        elif indicator_type == "domain":
            report = domain_report(str(indicator))
        else:
            report = ip_report(str(indicator))
    if indicator is None:
        raise click.ClickException("Indicator is required")
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"intel_virustotal_{_safe_name(str(indicator)[:32])}.json"
    )
    report = virustotal_payload(
        str(indicator), report, indicator_type=indicator_type, case_dir=case_dir, output=output
    )
    if output:
        write_json(output, report)
        _register_intel_output(
            case_dir=case_dir,
            output=output,
            category="intel-virustotal",
            source_command="intel virustotal",
            metadata={
                "indicator": indicator,
                "indicator_type": indicator_type,
                **(report.get("summary") or {}),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(report))


@intel.command("ioc")
@click.option("--input", "input_path", type=READABLE_FILE, required=True)
@click.option("--composite-rules", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def ioc_cmd(
    input_path: pathlib.Path,
    composite_rules: pathlib.Path | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("ioc_input_parse_failed", exc_info=True, path=str(input_path))
        raise click.ClickException("Invalid JSON input") from e
    rules = None
    if composite_rules is not None:
        try:
            parsed_rules = json.loads(composite_rules.read_text(encoding="utf-8"))
        except Exception as e:
            raise click.ClickException("Invalid composite rules JSON") from e
        rules = parsed_rules if isinstance(parsed_rules, list) else None
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"intel_ioc_{_safe_name(input_path.stem)}.json"
    )
    matches = [dataclasses.asdict(m) for m in detect_iocs(data, composite_rules=rules)]
    payload = ioc_payload(matches, input_path=input_path, case_dir=case_dir, output=output)
    if output:
        write_json(output, payload)
        _register_intel_output(
            case_dir=case_dir,
            output=output,
            category="intel-ioc",
            source_command="intel ioc",
            input_paths=[str(input_path)],
            metadata={"match_count": len(matches), **(payload.get("summary") or {})},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@intel.command("cve")
@click.option("--package", "package_name", required=True, type=ANDROID_PACKAGE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def cve_cmd(package_name: str, output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"intel_cve_{_safe_name(package_name)}.json"
    )
    data = cve_payload(
        package_name, correlate_cves_for_apk_package(package_name), case_dir=case_dir, output=output
    )
    if output:
        write_json(output, data)
        _register_intel_output(
            case_dir=case_dir,
            output=output,
            category="intel-cve",
            source_command="intel cve",
            metadata={"package": package_name, **(data.get("summary") or {})},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(data))


@intel.command("cve-risk")
@click.option("--sdk", type=int)
@click.option("--kernel-version")
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def cve_risk_cmd(
    sdk: int | None,
    kernel_version: str | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    if sdk is None and not kernel_version:
        raise click.ClickException("Provide --sdk and/or --kernel-version")
    data: dict[str, object] = {}
    if sdk is not None:
        data["android"] = android_cve_risk_score(sdk)
    if kernel_version:
        data["kernel"] = correlate_cves_for_kernel_version(kernel_version)
    android_data = _object_dict(data.get("android"))
    kernel_data = _object_dict(data.get("kernel"))
    summary = {
        "sdk": sdk,
        "kernel_version": kernel_version,
        "max_score": max(
            _score_value(android_data),
            _score_value(kernel_data),
        ),
    }
    data["summary"] = summary
    suffix = _safe_name(kernel_version or f"sdk_{sdk}")
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"intel_cve_risk_{suffix}.json"
    )
    if output:
        write_json(output, data)
        _register_intel_output(
            case_dir=case_dir,
            output=output,
            category="intel-cve-risk",
            source_command="intel cve-risk",
            metadata={"sdk": sdk, "kernel_version": kernel_version, **summary},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(data))


@intel.command("stix")
@click.option("--url", required=True)
@click.option("--db", "db_path", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def stix_cmd(
    url: str,
    db_path: pathlib.Path | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    if not url.strip().startswith("https://"):
        raise click.ClickException("Only https:// URLs are supported")
    matches = [dataclasses.asdict(m) for m in load_stix_indicators_from_url(url)]
    if db_path:
        recs = [
            IocRecord(ioc=m["ioc"], kind=m["kind"], source=url, first_seen=now()) for m in matches
        ]
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"intel_stix_{_safe_name(url)}.json"
    )
    payload = stix_payload(url, matches, case_dir=case_dir, output=output)
    if db_path:
        recs = [
            IocRecord(ioc=m["ioc"], kind=m["kind"], source=url, first_seen=now()) for m in matches
        ]
        payload["added"] = add_iocs(db_path, recs)
    if output:
        write_json(output, payload)
        _register_intel_output(
            case_dir=case_dir,
            output=output,
            category="intel-stix",
            source_command="intel stix",
            metadata={
                "url": url,
                "db_path": str(db_path) if db_path else None,
                "match_count": len(matches),
                **(payload.get("summary") or {}),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@intel.command("taxii")
@click.option("--api-root-url", required=True)
@click.option("--collection-id")
@click.option("--added-after")
@click.option("--token")
@click.option("--username")
@click.option("--password")
@click.option("--db", "db_path", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def taxii_cmd(
    api_root_url: str,
    collection_id: str | None,
    added_after: str | None,
    token: str | None,
    username: str | None,
    password: str | None,
    db_path: pathlib.Path | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    if not api_root_url.strip().startswith("https://"):
        raise click.ClickException("Only https:// URLs are supported")
    matches = [
        dataclasses.asdict(m)
        for m in load_taxii_indicators(
            api_root_url,
            collection_id=collection_id,
            added_after=added_after,
            token=token,
            username=username,
            password=password,
        )
    ]
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"intel_taxii_{_safe_name(collection_id or api_root_url)}.json"
    )
    payload = taxii_payload(
        api_root_url,
        matches,
        collection_id=collection_id,
        case_dir=case_dir,
        output=output,
        limit=None,
        token=token,
        username=username,
        password=password,
    )
    if db_path:
        recs = [
            IocRecord(ioc=m["ioc"], kind=m["kind"], source=api_root_url, first_seen=now())
            for m in matches
        ]
        payload["added"] = add_iocs(db_path, recs)
    if output:
        write_json(output, payload)
        _register_intel_output(
            case_dir=case_dir,
            output=output,
            category="intel-taxii",
            source_command="intel taxii",
            metadata={
                "api_root_url": api_root_url,
                "collection_id": collection_id,
                "db_path": str(db_path) if db_path else None,
                "match_count": len(matches),
                **(payload.get("summary") or {}),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@intel.command("ioc-db-list")
@click.option(
    "--db", "db_path", type=click.Path(dir_okay=False, path_type=pathlib.Path), required=True
)
@click.option("--limit", type=int, default=200)
def ioc_db_list_cmd(db_path: pathlib.Path, limit: int) -> None:
    rows = [dataclasses.asdict(r) for r in list_iocs(db_path, limit=limit)]
    console.print_json(json.dumps(rows))


@intel.command("ioc-db-sync")
@click.option(
    "--db", "db_path", type=click.Path(dir_okay=False, path_type=pathlib.Path), required=True
)
@click.option("--config", type=READABLE_FILE, required=True)
@click.option("--force", is_flag=True, help="Refresh even if feeds were synced recently.")
@click.option("--min-refresh-seconds", type=int, default=6 * 3600, show_default=True)
def ioc_db_sync_cmd(
    db_path: pathlib.Path, config: pathlib.Path, force: bool, min_refresh_seconds: int
) -> None:
    payload = sync_ioc_feeds(
        db_path, load_feed_config(config), force=force, min_refresh_seconds=min_refresh_seconds
    )
    console.print_json(json.dumps(payload))


@intel.command("reputation")
@click.option("--hash", "file_hash", type=HASH_HEX)
@click.option("--domain", type=DOMAIN)
@click.option("--ip", type=IPV4)
@click.option("--package", type=ANDROID_PACKAGE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def reputation_cmd(
    file_hash: str | None,
    domain: str | None,
    ip: str | None,
    package: str | None,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    payload: dict[str, object] = {}
    combined_score = 0

    if file_hash:
        try:
            vt = file_report(file_hash)
            payload["virustotal"] = vt
            stats = (
                (vt.get("attributes") or {}).get("last_analysis_stats")
                if isinstance(vt, dict)
                else None
            )
            if isinstance(stats, dict):
                malicious = int(stats.get("malicious") or 0)
                suspicious = int(stats.get("suspicious") or 0)
                combined_score += malicious * 10 + suspicious * 5
        except Exception as e:
            payload["virustotal_error"] = str(e)
        try:
            payload["otx_hash"] = indicator_reputation(file_hash)
        except OtxError as e:
            payload["otx_hash_error"] = str(e)

    if domain:
        try:
            payload["otx_domain"] = indicator_reputation(domain)
        except OtxError as e:
            payload["otx_domain_error"] = str(e)

    if ip:
        try:
            payload["otx_ip"] = indicator_reputation(ip)
        except OtxError as e:
            payload["otx_ip_error"] = str(e)

    if package:
        try:
            payload["osv"] = correlate_cves_for_apk_package(package)
        except Exception as e:
            payload["osv_error"] = str(e)

    payload["combined_score"] = combined_score
    subject = file_hash or domain or ip or package or "reputation"
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"intel_reputation_{_safe_name(subject)}.json"
    )
    if output:
        write_json(output, payload)
        _register_intel_output(
            case_dir=case_dir,
            output=output,
            category="intel-reputation",
            source_command="intel reputation",
            metadata={
                "hash": file_hash,
                "domain": domain,
                "ip": ip,
                "package": package,
                "combined_score": combined_score,
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))
