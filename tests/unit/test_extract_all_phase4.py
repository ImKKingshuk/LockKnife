import dataclasses
import json
import pathlib
import types
from typing import Any

from lockknife.core.exceptions import DeviceError
from lockknife_headless_cli._extract_all import run_extract_all


@dataclasses.dataclass
class _Row:
    value: str


@dataclasses.dataclass
class _LocationSnapshot:
    provider: str
    captured_at_ms: int


@dataclasses.dataclass
class _LocationBundle:
    snapshot: _LocationSnapshot
    wifi: list[_Row]
    cell: list[_Row]
    location_raw: str
    wifi_raw: str
    telephony_raw: str


class _Log:
    def warning(self, *args: Any, **kwargs: Any) -> None:
        return None


class _Cli:
    def __init__(self, *, fail_signal: bool = False) -> None:
        self.log = _Log()
        self.registrations: list[pathlib.Path] = []
        self._fail_signal = fail_signal

    def _rows(self, prefix: str) -> list[_Row]:
        return [_Row(f"{prefix}-1")]

    def extract_sms(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("sms")

    def extract_contacts(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("contacts")

    def extract_call_logs(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("calls")

    def extract_chrome_history(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("chrome-history")

    def extract_chrome_bookmarks(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("chrome-bookmarks")

    def extract_chrome_downloads(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("chrome-downloads")

    def extract_chrome_cookies(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("chrome-cookies")

    def extract_chrome_saved_logins(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("chrome-passwords")

    def extract_firefox_history(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("firefox-history")

    def extract_firefox_bookmarks(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("firefox-bookmarks")

    def extract_firefox_saved_logins(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("firefox-passwords")

    def extract_whatsapp_messages(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("whatsapp")

    def extract_telegram_messages(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("telegram")

    def extract_signal_messages(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        if self._fail_signal:
            raise DeviceError("signal unavailable")
        return self._rows("signal")

    def extract_media_with_exif(self, *_args: Any, **_kwargs: Any) -> list[_Row]:
        return self._rows("media")

    def extract_location_artifacts(self, *_args: Any, **_kwargs: Any) -> _LocationBundle:
        return _LocationBundle(
            snapshot=_LocationSnapshot(provider="gps", captured_at_ms=1234),
            wifi=[_Row("wifi-1")],
            cell=[_Row("cell-1")],
            location_raw="loc",
            wifi_raw="wifi",
            telephony_raw="telephony",
        )

    def register_case_artifact(self, *, path: pathlib.Path, **_kwargs: Any) -> None:
        self.registrations.append(path)


def test_run_extract_all_writes_json_outputs_and_registers_artifacts(tmp_path: pathlib.Path) -> None:
    cli = _Cli(fail_signal=True)
    progress_events: list[dict[str, Any]] = []

    written = run_extract_all(
        app=types.SimpleNamespace(devices=object()),
        cli=cli,
        serial="SER-1",
        limit=5,
        out_format="json",
        output_dir=tmp_path / "json-out",
        case_dir=tmp_path / "case",
        progress_callback=progress_events.append,
    )

    errors = json.loads((tmp_path / "json-out" / "errors.json").read_text(encoding="utf-8"))
    location = json.loads((tmp_path / "json-out" / "location.json").read_text(encoding="utf-8"))

    assert any(item["dataset"] == "signal_messages" for item in errors)
    assert location["snapshot"]["provider"] == "gps"
    assert len(cli.registrations) == len(written)
    assert progress_events[-1]["step"] == "register"


def test_run_extract_all_writes_csv_outputs_and_emits_completion(tmp_path: pathlib.Path) -> None:
    cli = _Cli()
    progress_events: list[dict[str, Any]] = []

    written = run_extract_all(
        app=types.SimpleNamespace(devices=object()),
        cli=cli,
        serial="SER-2",
        limit=3,
        out_format="csv",
        output_dir=tmp_path / "csv-out",
        case_dir=None,
        progress_callback=progress_events.append,
    )

    assert (tmp_path / "csv-out" / "sms.csv").exists()
    assert any(path.name == "location_snapshot.csv" for path in written)
    assert progress_events[-1]["step"] == "complete"