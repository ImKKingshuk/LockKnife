from __future__ import annotations

import pathlib
import subprocess
from types import SimpleNamespace

import pytest

from lockknife.core.case import create_case_workspace
from lockknife.core.execution_policy import (
    ExecutionGateway,
    ExecutionIntent,
    execution_intent_from_scope,
)


def _intent(case_dir: pathlib.Path, *, mode: str = "dry-run", status: str = "implemented-live"):
    return ExecutionIntent(
        operator="Tester",
        case_dir=case_dir,
        target="192.0.2.10",
        vector="adb_tcp",
        risk="high",
        mode=mode,
        capability_status=status,
        confirmed=mode == "lab-live",
    )


def test_execution_policy_requires_case_workspace(tmp_path: pathlib.Path) -> None:
    gateway = ExecutionGateway()
    decision = gateway.authorize(_intent(tmp_path / "missing"))
    assert decision.allowed is False
    assert "Case workspace" in decision.reason


def test_execution_gateway_dry_run_does_not_spawn_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-POL", examiner="Tester", title="Policy")

    def fail_run(*_args, **_kwargs):
        raise AssertionError("subprocess.run must not execute during dry-run")

    monkeypatch.setattr(subprocess, "run", fail_run)
    result = ExecutionGateway().run_subprocess(_intent(case_dir), ["echo", "hello"])

    assert result.dry_run is True
    assert result.return_code == 0


def test_execution_policy_fails_closed_for_poc_live(tmp_path: pathlib.Path) -> None:
    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-POC", examiner="Tester", title="Policy")
    decision = ExecutionGateway().authorize(_intent(case_dir, mode="lab-live", status="poc-only"))
    assert decision.allowed is False
    assert "cannot run live" in decision.reason


def test_adb_client_routes_dry_run_through_gateway(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    from lockknife.core.adb import AdbClient

    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-ADB", examiner="Tester", title="Policy")

    def fail_run(*_args, **_kwargs):
        raise AssertionError("subprocess.run must not execute during dry-run")

    monkeypatch.setattr(subprocess, "run", fail_run)

    out = AdbClient(execution_intent=_intent(case_dir)).shell("SERIAL", "id")

    assert out == ""


def test_http_dry_run_authorizes_without_network_or_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    from lockknife.core import http as http_mod

    case_dir = tmp_path / "case"
    create_case_workspace(case_dir=case_dir, case_id="CASE-HTTP", examiner="Tester", title="Policy")

    def fail_cache_root():
        raise AssertionError("cache must not be touched during dry-run")

    def fail_connection(*_args, **_kwargs):
        raise AssertionError("network must not be touched during dry-run")

    monkeypatch.setattr(http_mod, "_cache_root", fail_cache_root)
    monkeypatch.setattr(http_mod.http.client, "HTTPSConnection", fail_connection)

    assert (
        http_mod.http_get(
            "https://example.com/intel",
            cache_ttl_s=60.0,
            execution_intent=_intent(case_dir),
        )
        == b""
    )
    assert (
        http_mod.http_get_json(
            "https://example.com/intel.json",
            cache_ttl_s=60.0,
            execution_intent=_intent(case_dir),
        )
        is None
    )


def test_plugin_loader_dry_run_previews_without_import(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    from lockknife.core import plugin_loader

    case_dir = tmp_path / "case"
    create_case_workspace(
        case_dir=case_dir, case_id="CASE-PLUGIN", examiner="Tester", title="Policy"
    )

    monkeypatch.setenv(plugin_loader.PLUGIN_MODULES_ENV, "example_plugin")

    def fail_import(_spec: str):
        raise AssertionError("plugin module must not be imported during dry-run")

    monkeypatch.setattr(plugin_loader, "_entry_point_records", lambda: [])
    monkeypatch.setattr(plugin_loader, "_load_module_spec", fail_import)

    payload = plugin_loader.plugin_inventory(reload=True, execution_intent=_intent(case_dir))

    assert payload["loaded"] == []
    assert payload["failures"] == []
    assert payload["previews"]


def test_execution_intent_from_scope_maps_scope_fields(tmp_path: pathlib.Path) -> None:
    case_dir = tmp_path / "case"
    create_case_workspace(
        case_dir=case_dir, case_id="CASE-SCOPE", examiner="Tester", title="Policy"
    )
    scope = SimpleNamespace(
        operator="Tester",
        case_dir=case_dir,
        dry_run=False,
        lab_mode=True,
    )

    intent = execution_intent_from_scope(
        scope, target="192.0.2.10:5555", vector="adb_tcp", risk="safe"
    )

    assert intent.mode == "lab-live"
    assert intent.risk == "low"
    assert intent.confirmed is True
