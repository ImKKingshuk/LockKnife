from __future__ import annotations

import pathlib
import subprocess
import zipfile

import pytest

from lockknife.modules.apk import _decompile_tools as tools
from lockknife.modules.apk.decompile import ApkError, decompile_apk_report


def _apk(tmp_path: pathlib.Path) -> pathlib.Path:
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
    return apk


def test_auto_falls_back_through_both_failed_tools(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(tools.shutil, "which", lambda name: f"/tools/{name}")
    calls = []

    def fail(command, **kwargs):
        calls.append((command[0], kwargs["timeout"]))
        raise subprocess.CalledProcessError(1, command, stderr="failed stage")

    monkeypatch.setattr(tools.subprocess, "run", fail)
    result = tools.run_decompile_pipeline(
        _apk(tmp_path), tmp_path / "out", requested_mode="auto", timeout_s=9
    )
    assert calls == [("/tools/jadx", 9), ("/tools/apktool", 9)]
    assert result["effective_mode"] == "unpack"
    assert [stage["name"] for stage in result["failed_stages"]] == ["jadx", "apktool"]
    assert result["decompilation_depth"]["reconstructed_sources"] is False
    assert (tmp_path / "out" / "unpack" / "AndroidManifest.xml").exists()


@pytest.mark.parametrize(
    "error", [subprocess.TimeoutExpired(["jadx"], 3), FileNotFoundError("tool removed")]
)
def test_stage_failures_are_actionable(monkeypatch, tmp_path, error) -> None:
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(tools.subprocess, "run", fail)
    with pytest.raises(ApkError, match="timed out|Unable to run"):
        tools._run_external_stage("jadx", ["jadx"], tmp_path / "out", timeout_s=3)


def test_zero_exit_without_outputs_is_not_success(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        tools.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0)
    )
    with pytest.raises(ApkError, match="without producing files"):
        tools._run_external_stage("jadx", ["jadx"], tmp_path / "out")


def test_existing_output_is_preserved(tmp_path) -> None:
    output = tmp_path / "out"
    output.mkdir()
    evidence = output / "manifest.json"
    evidence.write_text("preserved evidence")
    with pytest.raises(ApkError, match="new or empty directory"):
        decompile_apk_report(_apk(tmp_path), output)
    assert evidence.read_text() == "preserved evidence"


def test_all_failed_stages_report_failure(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(tools.shutil, "which", lambda name: None)
    apk = tmp_path / "invalid.apk"
    apk.write_text("not a zip")
    with pytest.raises(ApkError, match="All decompile stages failed"):
        tools.run_decompile_pipeline(apk, tmp_path / "out", requested_mode="auto")


@pytest.mark.parametrize("timeout", [0, -1, 3601, float("nan"), float("inf")])
def test_pipeline_rejects_invalid_timeout(tmp_path, timeout) -> None:
    with pytest.raises(ApkError, match="timeout"):
        tools.run_decompile_pipeline(
            _apk(tmp_path), tmp_path / "out", requested_mode="auto", timeout_s=timeout
        )
