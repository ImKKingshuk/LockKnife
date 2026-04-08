from __future__ import annotations

import json
import pathlib
import time
from typing import Any

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from lockknife.core.case import load_case_manifest, register_case_artifact
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.cli_types import HASH_HEX, READABLE_FILE
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules.credentials.fido2 import pull_passkey_artifacts
from lockknife.modules.credentials.gesture import export_gesture_recovery, recover_gesture
from lockknife.modules.credentials.keystore import inspect_keystore, list_keystore
from lockknife.modules.credentials.password import crack_password_with_rules
from lockknife.modules.credentials.pin import export_pin_recovery, recover_pin
from lockknife.modules.credentials.wifi import export_wifi_credentials, extract_wifi_passwords
from lockknife_headless_cli._credential_workflows import (
    run_gesture_recovery_workflow,
    run_keystore_workflow,
    run_passkey_workflow,
    run_pin_recovery_workflow,
    run_wifi_workflow,
)


@click.group(help="Crack and recover credentials (offline or from device).", cls=LockKnifeGroup)
def crack() -> None:
    pass


@crack.command("pin")
@click.option("--hash", "target_hash", required=True, type=HASH_HEX)
@click.option(
    "--algo", type=click.Choice(["sha1", "sha256"], case_sensitive=False), default="sha256"
)
@click.option("--length", type=int, required=True)
def crack_pin(target_hash: str, algo: str, length: int) -> None:
    try:
        from lockknife import lockknife_core
    except Exception as e:
        raise click.ClickException("lockknife_core extension is not available") from e

    started = time.time()
    with Progress(
        SpinnerColumn(), BarColumn(), TextColumn("{task.description}"), transient=True
    ) as progress:
        progress.add_task(description="Brute-forcing PIN", total=None)
        pin = lockknife_core.bruteforce_numeric_pin(target_hash, algo.lower(), int(length))
    elapsed = time.time() - started

    if pin is None:
        raise click.ClickException(f"No PIN found (elapsed={elapsed:.2f}s)")

    console.print(f"{pin} (elapsed={elapsed:.2f}s)")


@crack.command("password")
@click.option("--hash", "target_hash", required=True, type=HASH_HEX)
@click.option(
    "--algo",
    type=click.Choice(["sha1", "sha256", "sha512"], case_sensitive=False),
    default="sha256",
)
@click.option("--wordlist", type=READABLE_FILE, required=True)
def crack_password(target_hash: str, algo: str, wordlist: pathlib.Path) -> None:
    try:
        from lockknife import lockknife_core
    except Exception as e:
        raise click.ClickException("lockknife_core extension is not available") from e

    found = lockknife_core.dictionary_attack(target_hash, algo.lower(), str(wordlist))
    if found is None:
        raise click.ClickException("No password found")
    console.print(found)


@crack.command("password-rules")
@click.option("--hash", "target_hash", required=True, type=HASH_HEX)
@click.option(
    "--algo",
    type=click.Choice(["sha1", "sha256", "sha512"], case_sensitive=False),
    default="sha256",
)
@click.option("--wordlist", type=READABLE_FILE, required=True)
@click.option("--max-suffix", type=int, default=100)
def crack_password_rules(
    target_hash: str, algo: str, wordlist: pathlib.Path, max_suffix: int
) -> None:
    found = crack_password_with_rules(target_hash, algo, wordlist, max_suffix=max_suffix)
    if found is None:
        raise click.ClickException("No password found")
    console.print(found)


@crack.command("gesture")
@click.option("-s", "--serial")
@click.option("--output-dir", type=click.Path(file_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def crack_gesture(
    app: Any, serial: str | None, output_dir: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    payload = run_gesture_recovery_workflow(
        app.devices,
        serial=serial,
        case_dir=case_dir,
        output_dir=output_dir,
        source_command="crack gesture",
        export_gesture_recovery=export_gesture_recovery,
        recover_gesture=recover_gesture,
        write_json=write_json,
        register_case_artifact=register_case_artifact,
        load_case_manifest=load_case_manifest,
    )
    console.print_json(json.dumps(payload))


@crack.command("pin-device")
@click.option("-s", "--serial")
@click.option("--length", type=int, required=True)
@click.option("--output-dir", type=click.Path(file_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def crack_pin_device(
    app: Any,
    serial: str | None,
    length: int,
    output_dir: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    started = time.time()
    payload = run_pin_recovery_workflow(
        app.devices,
        serial=serial,
        length=length,
        case_dir=case_dir,
        output_dir=output_dir,
        source_command="crack pin-device",
        export_pin_recovery=export_pin_recovery,
        recover_pin=recover_pin,
        write_json=write_json,
        register_case_artifact=register_case_artifact,
        load_case_manifest=load_case_manifest,
    )
    payload["elapsed_s"] = round(time.time() - started, 3)
    console.print_json(json.dumps(payload))


@crack.command("wifi")
@click.option("-s", "--serial")
@click.option("--output-dir", type=click.Path(file_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def crack_wifi(
    app: Any, serial: str | None, output_dir: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    payload = run_wifi_workflow(
        app.devices,
        serial=serial,
        case_dir=case_dir,
        output_dir=output_dir,
        source_command="crack wifi",
        export_wifi_credentials=export_wifi_credentials,
        extract_wifi_passwords=extract_wifi_passwords,
        write_json=write_json,
        register_case_artifact=register_case_artifact,
        load_case_manifest=load_case_manifest,
    )
    console.print_json(json.dumps(payload))


@crack.command("keystore")
@click.option("-s", "--serial")
@click.option("--output-dir", type=click.Path(file_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.pass_obj
def crack_keystore(
    app: Any, serial: str | None, output_dir: pathlib.Path | None, case_dir: pathlib.Path | None
) -> None:
    payload = run_keystore_workflow(
        app.devices,
        serial=serial,
        case_dir=case_dir,
        output_dir=output_dir,
        source_command="crack keystore",
        inspect_keystore=inspect_keystore,
        list_keystore=list_keystore,
        write_json=write_json,
        register_case_artifact=register_case_artifact,
        load_case_manifest=load_case_manifest,
    )
    console.print_json(json.dumps(payload))


@crack.command("passkeys")
@click.option("-s", "--serial")
@click.option("--output-dir", type=click.Path(file_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
@click.option("--limit", type=int, default=200)
@click.pass_obj
def crack_passkeys(
    app: Any,
    serial: str | None,
    output_dir: pathlib.Path | None,
    case_dir: pathlib.Path | None,
    limit: int,
) -> None:
    payload = run_passkey_workflow(
        app.devices,
        serial=serial,
        case_dir=case_dir,
        output_dir=output_dir,
        limit=limit,
        source_command="crack passkeys",
        pull_passkey_artifacts=pull_passkey_artifacts,
        write_json=write_json,
        register_case_artifact=register_case_artifact,
        load_case_manifest=load_case_manifest,
    )
    console.print_json(json.dumps(payload))
