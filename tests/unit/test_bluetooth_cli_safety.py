from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner

from lockknife_headless_cli.exploit.bluetooth import bluetooth


def _context(*, dry_run: bool) -> dict:
    manager = MagicMock()
    manager.validate_operation.return_value = (True, None)
    return {
        "scope": SimpleNamespace(dry_run=dry_run, scope_id="test-scope"),
        "auth_manager": manager,
    }


@pytest.mark.parametrize(
    "args",
    [["scan"], ["fingerprint", "--target", "test-device"], ["gatt", "--target", "test-device"]],
)
def test_bluetooth_dry_run_never_creates_live_clients(monkeypatch, args) -> None:
    from lockknife.modules.exploitation.bluetooth import fingerprint, gatt, scanner

    clients = [
        MagicMock(side_effect=AssertionError("Unexpected live Bluetooth client")) for _ in range(3)
    ]
    for module, name, client in zip(
        (fingerprint, gatt, scanner),
        ("BluetoothFingerprinter", "GATTClient", "BluetoothScanner"),
        clients,
        strict=True,
    ):
        monkeypatch.setattr(module, name, client)
    context = _context(dry_run=True)
    result = CliRunner().invoke(bluetooth, args, obj=context)
    assert result.exit_code == 0, result.output
    assert "No Bluetooth operation was executed" in result.output
    for client in clients:
        client.assert_not_called()
    assert (
        context["auth_manager"].record_operation.call_args.kwargs["metadata"]["executed"] is False
    )


def test_gatt_connection_failure_is_not_audited_as_success(monkeypatch) -> None:
    from lockknife.modules.exploitation.bluetooth import gatt

    backend = MagicMock()
    backend.connect = AsyncMock(return_value=SimpleNamespace(success=False, error="unavailable"))
    monkeypatch.setattr(gatt, "GATTClient", lambda: backend)
    context = _context(dry_run=False)
    result = CliRunner().invoke(bluetooth, ["gatt", "--target", "test-device"], obj=context)
    assert result.exit_code == 1
    assert context["auth_manager"].record_operation.call_args.kwargs["success"] is False


def test_gatt_invalid_write_is_rejected_before_connect(monkeypatch) -> None:
    from lockknife.modules.exploitation.bluetooth import gatt

    client = MagicMock(side_effect=AssertionError("Unexpected live Bluetooth client"))
    monkeypatch.setattr(gatt, "GATTClient", client)
    result = CliRunner().invoke(
        bluetooth,
        [
            "gatt",
            "--target",
            "test-device",
            "--operation",
            "write",
            "--uuid",
            "2a00",
            "--value",
            "invalid",
        ],
        obj=_context(dry_run=False),
    )
    assert result.exit_code == 2
    client.assert_not_called()
