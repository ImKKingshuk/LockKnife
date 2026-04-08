from __future__ import annotations

import dataclasses
import pathlib
from typing import Any

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from lockknife.core.exceptions import DeviceError
from lockknife.core.progress import ProgressCallback, emit_progress
from lockknife.core.serialize import write_csv, write_json

_RECOVERABLE_EXTRACT_ERRORS = (
    AttributeError,
    DeviceError,
    LookupError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)


def _extract_rows(
    dataset: str,
    *,
    cli: Any,
    app: Any,
    serial: str,
    progress_callback: ProgressCallback | None,
    current: int,
    total: int,
    extractor: Any,
    limit: int | None = None,
    errors: list[dict[str, str]],
) -> list[dict[str, Any]]:
    emit_progress(
        progress_callback,
        operation="extract.all",
        step=dataset,
        message=f"Extracting {dataset}",
        current=current,
        total=total,
        metadata={"dataset": dataset, "serial": serial, "limit": limit},
    )
    try:
        if limit is None:
            rows = extractor(app.devices, serial)
        else:
            rows = extractor(app.devices, serial, limit=limit)
        return [dataclasses.asdict(row) for row in rows]
    except _RECOVERABLE_EXTRACT_ERRORS as exc:
        errors.append({"dataset": dataset, "serial": serial})
        cli.log.warning(
            "extract_dataset_failed", exc_info=True, serial=serial, dataset=dataset, error=str(exc)
        )
        return []


def _extract_location_bundle(
    *,
    cli: Any,
    app: Any,
    serial: str,
    progress_callback: ProgressCallback | None,
    current: int,
    total: int,
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    emit_progress(
        progress_callback,
        operation="extract.all",
        step="location",
        message="Extracting location artifacts",
        current=current,
        total=total,
        metadata={"dataset": "location", "serial": serial},
    )
    try:
        loc = cli.extract_location_artifacts(app.devices, serial)
    except _RECOVERABLE_EXTRACT_ERRORS as exc:
        errors.append({"dataset": "location", "serial": serial})
        cli.log.warning("extract_location_failed", exc_info=True, serial=serial, error=str(exc))
        return {
            "snapshot": None,
            "wifi": [],
            "cell": [],
            "location_raw": None,
            "wifi_raw": None,
            "telephony_raw": None,
        }
    return {
        "snapshot": dataclasses.asdict(loc.snapshot),
        "wifi": [dataclasses.asdict(item) for item in loc.wifi],
        "cell": [dataclasses.asdict(item) for item in loc.cell],
        "location_raw": loc.location_raw,
        "wifi_raw": loc.wifi_raw,
        "telephony_raw": loc.telephony_raw,
    }


def run_extract_all(
    *,
    app: Any,
    cli: Any,
    serial: str,
    limit: int,
    out_format: str,
    output_dir: pathlib.Path,
    case_dir: pathlib.Path | None,
    progress_callback: ProgressCallback | None = None,
) -> list[pathlib.Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    errors: list[dict[str, str]] = []
    written_paths: list[pathlib.Path] = []

    def _write_json_tracked(path: pathlib.Path, data: Any) -> None:
        write_json(path, data)
        written_paths.append(path)

    def _write_csv_tracked(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
        write_csv(path, rows)
        written_paths.append(path)

    def _write_text_tracked(path: pathlib.Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        written_paths.append(path)

    total_steps = 10
    sms = _extract_rows(
        "sms",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=1,
        total=total_steps,
        extractor=cli.extract_sms,
        limit=limit,
        errors=errors,
    )
    contacts = _extract_rows(
        "contacts",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=2,
        total=total_steps,
        extractor=cli.extract_contacts,
        limit=limit,
        errors=errors,
    )
    calls = _extract_rows(
        "call_logs",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=3,
        total=total_steps,
        extractor=cli.extract_call_logs,
        limit=limit,
        errors=errors,
    )
    chrome_history = _extract_rows(
        "chrome_history",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=4,
        total=total_steps,
        extractor=cli.extract_chrome_history,
        limit=limit,
        errors=errors,
    )
    chrome_bookmarks = _extract_rows(
        "chrome_bookmarks",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=4,
        total=total_steps,
        extractor=cli.extract_chrome_bookmarks,
        limit=limit,
        errors=errors,
    )
    chrome_downloads = _extract_rows(
        "chrome_downloads",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=4,
        total=total_steps,
        extractor=cli.extract_chrome_downloads,
        limit=limit,
        errors=errors,
    )
    chrome_cookies = _extract_rows(
        "chrome_cookies",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=4,
        total=total_steps,
        extractor=cli.extract_chrome_cookies,
        limit=limit,
        errors=errors,
    )
    chrome_passwords = _extract_rows(
        "chrome_passwords",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=4,
        total=total_steps,
        extractor=cli.extract_chrome_saved_logins,
        limit=limit,
        errors=errors,
    )
    firefox_history = _extract_rows(
        "firefox_history",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=5,
        total=total_steps,
        extractor=cli.extract_firefox_history,
        limit=limit,
        errors=errors,
    )
    firefox_bookmarks = _extract_rows(
        "firefox_bookmarks",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=5,
        total=total_steps,
        extractor=cli.extract_firefox_bookmarks,
        limit=limit,
        errors=errors,
    )
    firefox_passwords = _extract_rows(
        "firefox_passwords",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=5,
        total=total_steps,
        extractor=cli.extract_firefox_saved_logins,
        limit=limit,
        errors=errors,
    )
    whatsapp_msgs = _extract_rows(
        "whatsapp_messages",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=6,
        total=total_steps,
        extractor=cli.extract_whatsapp_messages,
        limit=limit,
        errors=errors,
    )
    telegram_msgs = _extract_rows(
        "telegram_messages",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=6,
        total=total_steps,
        extractor=cli.extract_telegram_messages,
        limit=limit,
        errors=errors,
    )
    signal_msgs = _extract_rows(
        "signal_messages",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=6,
        total=total_steps,
        extractor=cli.extract_signal_messages,
        limit=limit,
        errors=errors,
    )
    media = _extract_rows(
        "media",
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=7,
        total=total_steps,
        extractor=cli.extract_media_with_exif,
        limit=min(limit, 200),
        errors=errors,
    )
    location = _extract_location_bundle(
        cli=cli,
        app=app,
        serial=serial,
        progress_callback=progress_callback,
        current=8,
        total=total_steps,
        errors=errors,
    )

    ext = "csv" if out_format.lower() == "csv" else "json"
    emit_progress(
        progress_callback,
        operation="extract.all",
        step="write",
        message="Writing extracted datasets",
        current=9,
        total=total_steps,
        metadata={"format": ext, "output_dir": str(output_dir)},
    )
    if ext == "csv":
        _write_csv_tracked(output_dir / "sms.csv", sms)
        _write_csv_tracked(output_dir / "contacts.csv", contacts)
        _write_csv_tracked(output_dir / "call_logs.csv", calls)
        if chrome_history:
            _write_csv_tracked(output_dir / "chrome_history.csv", chrome_history)
        if chrome_bookmarks:
            _write_csv_tracked(output_dir / "chrome_bookmarks.csv", chrome_bookmarks)
        if chrome_downloads:
            _write_csv_tracked(output_dir / "chrome_downloads.csv", chrome_downloads)
        if chrome_cookies:
            _write_csv_tracked(output_dir / "chrome_cookies.csv", chrome_cookies)
        if chrome_passwords:
            _write_csv_tracked(output_dir / "chrome_passwords.csv", chrome_passwords)
        if firefox_history:
            _write_csv_tracked(output_dir / "firefox_history.csv", firefox_history)
        if firefox_bookmarks:
            _write_csv_tracked(output_dir / "firefox_bookmarks.csv", firefox_bookmarks)
        if firefox_passwords:
            _write_csv_tracked(output_dir / "firefox_passwords.csv", firefox_passwords)
        if whatsapp_msgs:
            _write_csv_tracked(output_dir / "whatsapp_messages.csv", whatsapp_msgs)
        if telegram_msgs:
            _write_csv_tracked(output_dir / "telegram_messages.csv", telegram_msgs)
        if signal_msgs:
            _write_csv_tracked(output_dir / "signal_messages.csv", signal_msgs)
        if media:
            _write_csv_tracked(output_dir / "media.csv", media)
        if location["snapshot"]:
            _write_csv_tracked(output_dir / "location_snapshot.csv", [location["snapshot"]])
        if location["wifi"]:
            _write_csv_tracked(output_dir / "wifi.csv", location["wifi"])
        if location["cell"]:
            _write_csv_tracked(output_dir / "cell.csv", location["cell"])
        if location["location_raw"]:
            _write_text_tracked(output_dir / "dumpsys_location.txt", str(location["location_raw"]))
        if location["wifi_raw"]:
            _write_text_tracked(output_dir / "dumpsys_wifi.txt", str(location["wifi_raw"]))
        if location["telephony_raw"]:
            _write_text_tracked(
                output_dir / "dumpsys_telephony_registry.txt", str(location["telephony_raw"])
            )
        if errors:
            _write_csv_tracked(output_dir / "errors.csv", errors)
    else:
        _write_json_tracked(output_dir / "sms.json", sms)
        _write_json_tracked(output_dir / "contacts.json", contacts)
        _write_json_tracked(output_dir / "call_logs.json", calls)
        _write_json_tracked(
            output_dir / "browser_chrome.json",
            {
                "app": "chrome",
                "history": chrome_history,
                "bookmarks": chrome_bookmarks,
                "downloads": chrome_downloads,
                "cookies": chrome_cookies,
                "passwords": chrome_passwords,
            },
        )
        _write_json_tracked(
            output_dir / "browser_firefox.json",
            {
                "app": "firefox",
                "history": firefox_history,
                "bookmarks": firefox_bookmarks,
                "passwords": firefox_passwords,
            },
        )
        _write_json_tracked(output_dir / "whatsapp_messages.json", whatsapp_msgs)
        _write_json_tracked(output_dir / "telegram_messages.json", telegram_msgs)
        _write_json_tracked(output_dir / "signal_messages.json", signal_msgs)
        _write_json_tracked(output_dir / "media.json", media)
        _write_json_tracked(output_dir / "location.json", location)
        if errors:
            _write_json_tracked(output_dir / "errors.json", errors)

    if case_dir is not None:
        emit_progress(
            progress_callback,
            operation="extract.all",
            step="register",
            message="Registering extracted outputs in case manifest",
            current=10,
            total=total_steps,
            metadata={"path_count": len(written_paths)},
        )
        for written_path in written_paths:
            cli.register_case_artifact(
                case_dir=case_dir,
                path=written_path,
                category="extract-all-output",
                source_command="extract all",
                device_serial=serial,
                metadata={
                    "dataset": written_path.stem,
                    "format": written_path.suffix.lstrip("."),
                    "limit": limit,
                },
            )
    else:
        emit_progress(
            progress_callback,
            operation="extract.all",
            step="complete",
            message="Extraction completed",
            current=10,
            total=total_steps,
            metadata={"path_count": len(written_paths)},
        )
    return written_paths


def register(extract: Any, cli: Any) -> None:
    @extract.command("all")
    @click.option("-s", "--serial", required=True)
    @click.option("--limit", type=int, default=200)
    @click.option(
        "--format",
        "out_format",
        type=click.Choice(["json", "csv"], case_sensitive=False),
        default="json",
    )
    @click.option("--output-dir", type=click.Path(file_okay=False, path_type=pathlib.Path))
    @click.option(
        "--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path)
    )
    @click.pass_obj
    def extract_all_cmd(
        app: Any,
        serial: str,
        limit: int,
        out_format: str,
        output_dir: pathlib.Path | None,
        case_dir: pathlib.Path | None,
    ) -> None:
        derived = False
        if output_dir is None:
            if case_dir is None:
                raise click.ClickException("Either --output-dir or --case-dir is required")
            output_dir = case_dir / "evidence" / f"extract_all_{serial}"
            derived = True
        with Progress(
            SpinnerColumn(), BarColumn(), TextColumn("{task.description}"), transient=True
        ) as progress:
            task = progress.add_task(description="Extracting datasets", total=None)

            def _on_progress(event: dict[str, Any]) -> None:
                progress.update(
                    task, description=str(event.get("message") or "Extracting datasets")
                )

            run_extract_all(
                app=app,
                cli=cli,
                serial=serial,
                limit=limit,
                out_format=out_format,
                output_dir=output_dir,
                case_dir=case_dir,
                progress_callback=_on_progress,
            )
        if derived:
            cli.console.print(str(output_dir))
