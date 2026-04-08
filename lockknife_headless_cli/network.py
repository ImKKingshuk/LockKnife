from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from lockknife.core.case import case_output_path, register_case_artifact
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.cli_types import READABLE_FILE
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules._case_enrichment_payloads import (
    api_discovery_payload,
    network_summary_payload,
)
from lockknife.modules.network.api_discovery import extract_api_endpoints_from_pcap, summarize_pcap
from lockknife.modules.network.capture import capture_pcap
from lockknife.modules.network.parser import parse_ipv4_header


@click.group(help="Network analysis helpers.", cls=LockKnifeGroup)
def network() -> None:
    pass


def _resolve_case_output(
    output: pathlib.Path | None, case_dir: pathlib.Path | None, *, area: str, filename: str
) -> tuple[pathlib.Path | None, bool]:
    if output is not None:
        return output, False
    if case_dir is None:
        return None, False
    return case_output_path(case_dir, area=area, filename=filename), True


def _register_network_output(
    *,
    case_dir: pathlib.Path | None,
    output: pathlib.Path,
    category: str,
    source_command: str,
    device_serial: str | None = None,
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
        device_serial=device_serial,
        input_paths=input_paths,
        metadata=metadata,
    )


@network.command("parse-ipv4")
@click.argument("packet_hex")
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def parse_ipv4_cmd(
    packet_hex: str, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    data = bytes.fromhex(packet_hex)
    parsed = parse_ipv4_header(data)
    output, derived = _resolve_case_output(
        output, case_dir, area="derived", filename="network_parse_ipv4.json"
    )
    if output:
        write_json(output, parsed)
        _register_network_output(
            case_dir=case_dir,
            output=output,
            category="network-parse-ipv4",
            source_command="network parse-ipv4",
            metadata={"packet_hex_length": len(packet_hex)},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(parsed))


@network.command("capture")
@click.option("-s", "--serial", required=True)
@click.option("--duration", "duration_s", type=float, default=30.0)
@click.option("--iface", default="any")
@click.option("--snaplen", type=int, default=0)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def capture_cmd(
    app: Any,
    serial: str,
    duration_s: float,
    iface: str,
    snaplen: int,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    output, _derived = _resolve_case_output(
        output, case_dir, area="evidence", filename=f"network_capture_{serial}.pcap"
    )
    if output is None:
        raise click.ClickException("Either --output or --case-dir is required")
    with Progress(
        SpinnerColumn(), BarColumn(), TextColumn("{task.description}"), transient=True
    ) as progress:
        task = progress.add_task(description="Capturing packets", total=None)

        def _on_progress(event: dict[str, Any]) -> None:
            progress.update(task, description=str(event.get("message") or "Capturing packets"))

        res = capture_pcap(
            app.devices,
            serial,
            output_path=output,
            duration_s=duration_s,
            iface=iface,
            snaplen=snaplen,
            progress_callback=_on_progress,
        )
    metadata: dict[str, object] = {"duration_s": duration_s, "iface": iface, "snaplen": snaplen}
    remote_path = getattr(res, "remote_path", None)
    if remote_path is not None:
        metadata["remote_path"] = remote_path
    _register_network_output(
        case_dir=case_dir,
        output=output,
        category="network-capture",
        source_command="network capture",
        device_serial=serial,
        metadata=metadata,
    )
    console.print_json(json.dumps(dataclasses.asdict(res)))


@network.command("analyze")
@click.argument("pcap_path", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def analyze_cmd(
    pcap_path: pathlib.Path, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    output, derived = _resolve_case_output(
        output, case_dir, area="derived", filename=f"network_analyze_{pcap_path.stem}.json"
    )
    payload = network_summary_payload(
        summarize_pcap(pcap_path), input_path=pcap_path, case_dir=case_dir, output=output
    )
    if output:
        write_json(output, payload)
        _register_network_output(
            case_dir=case_dir,
            output=output,
            category="network-analysis",
            source_command="network analyze",
            input_paths=[str(pcap_path)],
            metadata={"pcap": str(pcap_path), **(payload.get("summary") or {})},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@network.command("api-discovery")
@click.argument("pcap_path", type=READABLE_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def api_discovery_cmd(
    pcap_path: pathlib.Path, output: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    output, derived = _resolve_case_output(
        output, case_dir, area="derived", filename=f"network_api_discovery_{pcap_path.stem}.json"
    )
    payload = api_discovery_payload(
        extract_api_endpoints_from_pcap(pcap_path),
        input_path=pcap_path,
        case_dir=case_dir,
        output=output,
    )
    if output:
        write_json(output, payload)
        _register_network_output(
            case_dir=case_dir,
            output=output,
            category="network-api-discovery",
            source_command="network api-discovery",
            input_paths=[str(pcap_path)],
            metadata={"pcap": str(pcap_path), **(payload.get("summary") or {})},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))
