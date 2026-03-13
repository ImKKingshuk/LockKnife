from __future__ import annotations

import json
import pathlib
from typing import Any

import click
from rich.console import Console

from lockknife.core.case import (
    case_chain_of_custody_items,
    case_chain_of_custody_report,
    case_integrity_report,
    case_output_path,
    find_case_artifact,
    generate_case_chain_of_custody,
    load_case_manifest,
    register_case_artifact,
    summarize_case_manifest,
)
from lockknife.modules.reporting.chain_of_custody import EvidenceItem, build_chain_of_custody_payload, generate_chain_of_custody, sign_report_file
from lockknife.modules.reporting.context import build_report_context
from lockknife.modules.reporting.csv_export import export_csv
from lockknife.modules.reporting.html_report import write_html_report
from lockknife.modules.reporting.json_export import export_json
from lockknife.modules.reporting.pdf_report import write_pdf_report


console = Console()


def _case_path(case_dir: str | None) -> pathlib.Path | None:
    return pathlib.Path(case_dir) if case_dir else None


def _resolve_manifest(case_path: pathlib.Path | None) -> Any | None:
    return load_case_manifest(case_path) if case_path else None


def _resolve_case_id(case_id: str | None, case_path: pathlib.Path | None) -> str:
    manifest = _resolve_manifest(case_path)
    if case_id:
        return case_id
    if manifest:
        return str(manifest.case_id)
    raise click.BadParameter("--case-id is required unless --case-dir points to a LockKnife case workspace")


def _resolve_examiner(examiner: str | None, case_path: pathlib.Path | None) -> str:
    manifest = _resolve_manifest(case_path)
    if examiner:
        return examiner
    if manifest:
        return str(manifest.examiner)
    raise click.BadParameter("--examiner is required unless --case-dir points to a LockKnife case workspace")


def _default_output(case_path: pathlib.Path | None, *, filename: str) -> pathlib.Path:
    if not case_path:
        raise click.BadParameter("--output is required unless --case-dir points to a LockKnife case workspace")
    return case_output_path(case_path, area="reports", filename=filename)


def _artifact_payload(path: str | None, case_path: pathlib.Path | None) -> Any:
    if path:
        return json.loads(pathlib.Path(path).read_text())
    if case_path:
        return summarize_case_manifest(case_path)
    raise click.BadParameter("--artifacts is required unless --case-dir points to a LockKnife case workspace")


def _template_path(template: str) -> pathlib.Path:
    template_l = template.lower()
    if template_l == "executive":
        name = "executive_report.html"
    elif template_l == "chain_of_custody":
        name = "chain_of_custody.html"
    else:
        name = "technical_report.html"
    return pathlib.Path(__file__).resolve().parents[1] / "lockknife" / "templates" / name


def _csv_rows(artifacts: Any, context: dict[str, object]) -> list[dict[str, object]]:
    if isinstance(artifacts, list) and all(isinstance(row, dict) for row in artifacts):
        return artifacts
    evidence_inventory = context.get("evidence_inventory")
    if isinstance(evidence_inventory, list) and evidence_inventory:
        return [row for row in evidence_inventory if isinstance(row, dict)]
    if isinstance(artifacts, dict):
        return [artifacts]
    return [{"value": artifacts}]


def _register_output(
    case_path: pathlib.Path | None,
    *,
    output_path: pathlib.Path,
    category: str,
    source_command: str,
    case_id: str,
    input_paths: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    if not case_path:
        return
    register_case_artifact(
        case_dir=case_path,
        path=output_path,
        category=category,
        source_command=source_command,
        input_paths=input_paths or [],
        metadata={"case_id": case_id, **(metadata or {})},
    )


def _manual_evidence(case_path: pathlib.Path | None, evidence: tuple[str, ...]) -> list[EvidenceItem]:
    if not case_path:
        return [EvidenceItem(name=pathlib.Path(path).name, path=path) for path in evidence]

    items: list[EvidenceItem] = []
    for path in evidence:
        artifact = find_case_artifact(case_path, path=path)
        if artifact:
            items.extend(case_chain_of_custody_items(case_path, artifacts=[artifact]))
        else:
            items.append(EvidenceItem(name=pathlib.Path(path).name, path=path))
    return items


def _render_integrity_text(report: dict[str, object]) -> str:
    summary = report["summary"]
    if not isinstance(summary, dict):
        raise click.ClickException("Integrity report summary is malformed")
    custody_chain_obj = report.get("custody_chain")
    custody_chain: dict[str, object] = custody_chain_obj if isinstance(custody_chain_obj, dict) else {}
    verification_obj = custody_chain.get("verification")
    verification: dict[str, object] = verification_obj if isinstance(verification_obj, dict) else {}
    lines = [
        f"Case integrity report: {report['case_id']}",
        f"Examiner: {report['examiner']}",
        f"Verified at: {report['verified_at_utc']}",
        "",
        "Summary:",
        f"- Artifacts: {summary['artifact_count']}",
        f"- Verified: {summary['verified_count']}",
        f"- Modified: {summary['modified_count']}",
        f"- Missing: {summary['missing_count']}",
        f"- Unreadable: {summary['unreadable_count']}",
        f"- Unsupported: {summary['unsupported_count']}",
        f"- Custody chain: {summary.get('custody_chain_status', 'unknown')}",
        "",
        "Custody chain:",
        f"- Entries: {custody_chain.get('entry_count', 0)}",
        f"- Chain head: {custody_chain.get('chain_head_sha256') or 'n/a'}",
        f"- Verification: {verification.get('status', 'unknown')}",
        "",
        f"Advisory: {report['advisory']}",
    ]
    return "\n".join(lines) + "\n"


@click.group(help="Generate reports (HTML/PDF/CSV/JSON)")
def report() -> None:
    pass


@report.command("generate")
@click.option("--case-id", required=False)
@click.option("--artifacts", type=click.Path(exists=True, dir_okay=False), required=False)
@click.option("--template", type=click.Choice(["technical", "executive"]), default="technical")
@click.option("--format", "out_format", type=click.Choice(["html", "pdf", "json", "csv"]), default="html")
@click.option("--output", type=click.Path(dir_okay=False), required=False)
@click.option("--case-dir", type=click.Path(exists=True, file_okay=False, dir_okay=True), required=False)
def generate(case_id: str | None, artifacts: str | None, template: str, out_format: str, output: str | None, case_dir: str | None) -> None:
    case_path = _case_path(case_dir)
    resolved_case_id = _resolve_case_id(case_id, case_path)
    artifact_data = _artifact_payload(artifacts, case_path)
    context = build_report_context(case_id=resolved_case_id, artifacts=artifact_data, case_dir=case_path)
    output_path = pathlib.Path(output) if output else _default_output(case_path, filename=f"{template}_{resolved_case_id}.{out_format}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    final_output_path = output_path
    final_format = out_format
    degraded = False

    if out_format == "html":
        write_html_report(_template_path(template), context, output_path)
    elif out_format == "pdf":
        pdf_result = write_pdf_report(
            _template_path(template),
            context,
            output_path,
            fallback_html_path=output_path.with_suffix(".html"),
        )
        final_output_path = pathlib.Path(str(pdf_result["output"]))
        final_format = str(pdf_result["format"])
        degraded = bool(pdf_result.get("degraded"))
    elif out_format == "json":
        export_json(context, output_path)
    else:
        export_csv(_csv_rows(artifact_data, context), output_path)

    _register_output(
        case_path,
        output_path=final_output_path,
        category=f"report-{final_format}",
        source_command="report generate",
        case_id=resolved_case_id,
        input_paths=[artifacts] if artifacts else [],
        metadata={"template": template, "format": final_format, "requested_format": out_format, "degraded": degraded},
    )
    click.echo(str(final_output_path))


@report.command("chain-of-custody")
@click.option("--case-id", required=False)
@click.option("--examiner", required=False)
@click.option("--evidence", multiple=True, type=click.Path(), required=False)
@click.option("--output", type=click.Path(dir_okay=False), required=False)
@click.option("--notes", default="")
@click.option("--format", "out_format", type=click.Choice(["text", "html"]), default="text")
@click.option("--sign", is_flag=True, default=False)
@click.option("--gpg-key-id", required=False)
@click.option("--case-dir", type=click.Path(exists=True, file_okay=False, dir_okay=True), required=False)
def chain_of_custody(case_id: str | None, examiner: str | None, evidence: tuple[str, ...], output: str | None, notes: str, out_format: str, sign: bool, gpg_key_id: str | None, case_dir: str | None) -> None:
    case_path = _case_path(case_dir)
    resolved_case_id = _resolve_case_id(case_id, case_path)
    resolved_examiner = _resolve_examiner(examiner, case_path)
    evidence_items = _manual_evidence(case_path, evidence) if evidence else None
    suffix = "html" if out_format == "html" else "txt"
    output_path = pathlib.Path(output) if output else _default_output(case_path, filename=f"chain_of_custody_{resolved_case_id}.{suffix}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if case_path and evidence_items is None:
        payload = case_chain_of_custody_report(case_path, notes=notes or None)
        evidence_items = case_chain_of_custody_items(case_path)
    else:
        payload = build_chain_of_custody_payload(
            case_id=resolved_case_id,
            examiner=resolved_examiner,
            notes=notes or None,
            evidence=evidence_items or [],
        )
    if out_format == "html":
        write_html_report(_template_path("chain_of_custody"), {"report_title": "Chain of Custody", **payload}, output_path)
    else:
        output_path.write_text(
            generate_chain_of_custody(
                case_id=resolved_case_id,
                examiner=resolved_examiner,
                notes=notes or None,
                evidence=evidence_items or [],
            ),
            encoding="utf-8",
        )
    signature = sign_report_file(output_path, key_id=gpg_key_id) if sign else {"status": "not-requested"}

    _register_output(
        case_path,
        output_path=output_path,
        category="chain-of-custody",
        source_command="report chain-of-custody",
        case_id=resolved_case_id,
        metadata={"evidence_count": int(payload.get("entry_count", 0)), "format": out_format, "signature_status": signature.get("status")},
    )
    if case_path and signature.get("status") == "signed" and signature.get("signature_path"):
        _register_output(
            case_path,
            output_path=pathlib.Path(str(signature["signature_path"])),
            category="chain-of-custody-signature",
            source_command="report chain-of-custody",
            case_id=resolved_case_id,
            metadata={"signed_output": str(output_path)},
        )
    click.echo(str(output_path))


@report.command("integrity")
@click.option("--case-dir", type=click.Path(exists=True, file_okay=False, dir_okay=True), required=True)
@click.option("--format", "out_format", type=click.Choice(["json", "text"]), default="json")
@click.option("--output", type=click.Path(dir_okay=False), required=False)
def integrity(case_dir: str, out_format: str, output: str | None) -> None:
    case_path = pathlib.Path(case_dir)
    manifest = load_case_manifest(case_path)
    report_payload = case_integrity_report(case_path)
    suffix = "json" if out_format == "json" else "txt"
    output_path = pathlib.Path(output) if output else _default_output(case_path, filename=f"integrity_{manifest.case_id}.{suffix}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if out_format == "json":
        export_json(report_payload, output_path)
    else:
        output_path.write_text(_render_integrity_text(report_payload), encoding="utf-8")

    _register_output(
        case_path,
        output_path=output_path,
        category="report-integrity",
        source_command="report integrity",
        case_id=manifest.case_id,
        metadata={"format": out_format},
    )
    click.echo(str(output_path))