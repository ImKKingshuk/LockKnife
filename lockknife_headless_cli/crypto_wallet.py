from __future__ import annotations

import dataclasses
import json
import pathlib
import re
from typing import Any

import click

from lockknife.core.adb import AdbClient
from lockknife.core.case import case_output_path, register_case_artifact
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.cli_types import READABLE_FILE
from lockknife.core.device import DeviceManager
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules.crypto_wallet.wallet import (
    enrich_wallet_addresses,
    extract_device_wallets,
    extract_mnemonics,
    extract_wallet_addresses_from_sqlite,
    extract_web3_keystores,
)


@click.group(help="Crypto wallet forensics.", cls=LockKnifeGroup)
def crypto_wallet() -> None:
    pass


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "wallet"


def _resolve_case_output(
    output: pathlib.Path | None, case_dir: pathlib.Path | None, *, filename: str
) -> tuple[pathlib.Path | None, bool]:
    if output is not None:
        return output, False
    if case_dir is None:
        return None, False
    return case_output_path(case_dir, area="derived", filename=filename), True


def _register_wallet_output(
    *,
    case_dir: pathlib.Path | None,
    output: pathlib.Path,
    source_command: str = "crypto-wallet wallet",
    input_paths: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    if case_dir is None:
        return
    register_case_artifact(
        case_dir=case_dir,
        path=output,
        category="crypto-wallet",
        source_command=source_command,
        input_paths=input_paths,
        metadata=metadata,
    )


@crypto_wallet.command("wallet")
@click.argument("db_path", type=READABLE_FILE)
@click.option("--lookup", "do_lookup", is_flag=True, default=False)
@click.option(
    "--carve-seeds", is_flag=True, default=False, help="Carve BIP-39 mnemonic seed phrases."
)
@click.option(
    "--carve-vaults",
    is_flag=True,
    default=False,
    help="Carve Web3 keystore and wallet vault blobs.",
)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def wallet_cmd(
    db_path: pathlib.Path,
    do_lookup: bool,
    carve_seeds: bool,
    carve_vaults: bool,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    addrs = extract_wallet_addresses_from_sqlite(db_path)
    if do_lookup:
        addr_rows = enrich_wallet_addresses(addrs)
    else:
        addr_rows = [dataclasses.asdict(r) for r in addrs]

    mnemonics = extract_mnemonics(db_path.read_bytes(), source=str(db_path)) if carve_seeds else []
    vaults = (
        extract_web3_keystores(db_path.read_bytes(), source=str(db_path)) if carve_vaults else []
    )

    if carve_seeds or carve_vaults:
        payload: Any = {
            "addresses": addr_rows,
            "mnemonics": [dataclasses.asdict(m) for m in mnemonics],
            "vaults": [dataclasses.asdict(v) for v in vaults],
        }
    else:
        payload = addr_rows

    output, derived = _resolve_case_output(
        output, case_dir, filename=f"crypto_wallet_{_safe_name(db_path.stem)}.json"
    )
    if output:
        write_json(output, payload)
        _register_wallet_output(
            case_dir=case_dir,
            output=output,
            input_paths=[str(db_path)],
            metadata={
                "lookup": do_lookup,
                "address_count": len(addrs),
                "mnemonic_count": len(mnemonics),
                "vault_count": len(vaults),
            },
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(payload))


@crypto_wallet.command("scan-device")
@click.option("-s", "--serial", required=True, help="Target device serial.")
@click.option("--limit", type=int, default=20, help="Max files per wallet app to extract.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def scan_device_cmd(
    app: Any,
    serial: str,
    limit: int,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    devices = getattr(app, "devices", None) or DeviceManager(AdbClient())
    wallets = extract_device_wallets(devices, serial, limit_files_per_app=limit)
    rows = [dataclasses.asdict(w) for w in wallets]
    output, derived = _resolve_case_output(
        output, case_dir, filename=f"crypto_wallets_{_safe_name(serial)}.json"
    )
    if output:
        write_json(output, rows)
        _register_wallet_output(
            case_dir=case_dir,
            output=output,
            source_command="crypto-wallet scan-device",
            metadata={"serial": serial, "wallet_count": len(rows), "limit": limit},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(rows))
