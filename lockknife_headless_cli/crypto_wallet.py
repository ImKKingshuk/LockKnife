from __future__ import annotations

import dataclasses
import json
import pathlib
import re

import click

from lockknife.core.case import case_output_path, register_case_artifact
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.cli_types import READABLE_FILE
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules.crypto_wallet.wallet import enrich_wallet_addresses, extract_wallet_addresses_from_sqlite


@click.group(help="Crypto wallet forensics.", cls=LockKnifeGroup)
def crypto_wallet() -> None:
    pass


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "wallet"


def _resolve_case_output(output: pathlib.Path | None, case_dir: pathlib.Path | None, *, filename: str) -> tuple[pathlib.Path | None, bool]:
    if output is not None:
        return output, False
    if case_dir is None:
        return None, False
    return case_output_path(case_dir, area="derived", filename=filename), True


def _register_wallet_output(
    *,
    case_dir: pathlib.Path | None,
    output: pathlib.Path,
    input_paths: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    if case_dir is None:
        return
    register_case_artifact(
        case_dir=case_dir,
        path=output,
        category="crypto-wallet",
        source_command="crypto-wallet wallet",
        input_paths=input_paths,
        metadata=metadata,
    )


@crypto_wallet.command("wallet")
@click.argument("db_path", type=READABLE_FILE)
@click.option("--lookup", "do_lookup", is_flag=True, default=False)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def wallet_cmd(db_path: pathlib.Path, do_lookup: bool, output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
    addrs = extract_wallet_addresses_from_sqlite(db_path)
    if do_lookup:
        rows = enrich_wallet_addresses(addrs)
    else:
        rows = [dataclasses.asdict(r) for r in addrs]
    output, derived = _resolve_case_output(output, case_dir, filename=f"crypto_wallet_{_safe_name(db_path.stem)}.json")
    if output:
        write_json(output, rows)
        _register_wallet_output(
            case_dir=case_dir,
            output=output,
            input_paths=[str(db_path)],
            metadata={"lookup": do_lookup, "address_count": len(addrs), "row_count": len(rows)},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(rows))
