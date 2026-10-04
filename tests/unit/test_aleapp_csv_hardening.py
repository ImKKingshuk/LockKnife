from __future__ import annotations

import pathlib

from lockknife.modules.forensics.aleapp_compat import (
    import_aleapp_artifacts,
    looks_like_aleapp_output,
)


def test_looks_like_aleapp_output_with_csv(tmp_path: pathlib.Path) -> None:
    assert looks_like_aleapp_output(tmp_path) is False

    cat_dir = tmp_path / "Device Information"
    cat_dir.mkdir(parents=True, exist_ok=True)
    csv_file = cat_dir / "build_props.csv"
    csv_file.write_text("Property,Value\nro.build.version.release,14\n", encoding="utf-8")

    assert looks_like_aleapp_output(tmp_path) is True


def test_import_mixed_tsv_and_csv(tmp_path: pathlib.Path) -> None:
    (tmp_path / "calls.tsv").write_text("Number\tType\n123\tIncoming\n")
    (tmp_path / "packages.csv").write_text("Package Name,Version\norg.example.app,1\n")
    imported = import_aleapp_artifacts(tmp_path)
    assert imported["summary"]["source_format_counts"] == {"tsv": 1, "csv": 1}
    assert imported["summary"]["artifact_count"] == 2


def test_import_aleapp_artifacts_csv(tmp_path: pathlib.Path) -> None:
    cat_dir = tmp_path / "Call Logs"
    cat_dir.mkdir(parents=True, exist_ok=True)
    csv_file = cat_dir / "calls.csv"
    csv_file.write_text(
        "Number,Type,Date,Duration\n"
        "+15551234567,Incoming,2026-03-01 10:00:00,120\n"
        "+15559876543,Outgoing,2026-03-01 11:30:00,45\n",
        encoding="utf-8",
    )

    imported = import_aleapp_artifacts(tmp_path)
    assert imported["summary"]["artifact_count"] == 1
    assert "csv" in imported["summary"]["source_format_counts"]
    assert imported["summary"]["source_format_counts"]["csv"] == 1

    art = imported["artifacts"][0]
    assert art["artifact_family"] == "call_logs"
    assert len(art["records"]) == 2
    assert art["records"][0]["number"] == "+15551234567"
    assert art["records"][0]["duration"] == "120"


def test_import_aleapp_artifacts_csv_semicolon_delimited(tmp_path: pathlib.Path) -> None:
    cat_dir = tmp_path / "Installed Apps"
    cat_dir.mkdir(parents=True, exist_ok=True)
    csv_file = cat_dir / "packages.csv"
    csv_file.write_text(
        "Package Name;Version;Install Date\norg.example.app;1.2.0;2026-01-15\n",
        encoding="utf-8",
    )

    imported = import_aleapp_artifacts(tmp_path)
    assert imported["summary"]["artifact_count"] == 1
    art = imported["artifacts"][0]
    assert len(art["records"]) == 1
    assert art["records"][0]["package_name"] == "org.example.app"
    assert art["records"][0]["version"] == "1.2.0"
