from __future__ import annotations

import dataclasses
import json
import pathlib

import click

from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.logging import get_logger
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules.forensics.artifacts import parse_directory_as_aleapp
from lockknife.modules.intelligence.ioc import detect_iocs
from lockknife.modules.security.malware import scan_with_patterns


@click.group(help="Analyze extracted artifacts and local evidence.", cls=LockKnifeGroup)
def analyze() -> None:
    pass

log = get_logger()


@analyze.command("evidence")
@click.option("--dir", "input_dir", type=click.Path(file_okay=False, path_type=pathlib.Path), required=True)
@click.option("--pattern", "patterns", multiple=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
def evidence_cmd(input_dir: pathlib.Path, patterns: tuple[str, ...], output: pathlib.Path | None) -> None:
    artifacts = parse_directory_as_aleapp(input_dir)
    all_records = []
    for a in artifacts:
        all_records.extend(a.records)
    iocs = [dataclasses.asdict(m) for m in detect_iocs(all_records)]
    pat_hits = []
    for p in input_dir.glob("*.dex"):
        try:
            pat_hits.append({"file": str(p), "hits": scan_with_patterns(list(patterns), p)})
        except Exception:
            log.debug("evidence_dex_scan_failed", exc_info=True, path=str(p))
            continue
    payload = {"artifacts": [dataclasses.asdict(a) for a in artifacts], "iocs": iocs, "pattern_hits": pat_hits}
    if output:
        write_json(output, payload)
        return
    console.print_json(json.dumps(payload))
