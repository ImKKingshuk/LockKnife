import types

from click.testing import CliRunner


class _State(str):
    @property
    def value(self) -> str:
        return str(self)


def _console() -> types.SimpleNamespace:
    return types.SimpleNamespace(print_json=lambda *_a, **_k: None, print=lambda *_a, **_k: None)


def test_device_cli_commands(monkeypatch) -> None:
    from lockknife_headless_cli import device as device_cli

    handles = [
        types.SimpleNamespace(serial="S1", adb_state="device", state=_State("ready"), model="Pixel", device="redfin", transport_id="1"),
        types.SimpleNamespace(serial="S2", adb_state="offline", state=_State("offline"), model=None, device=None, transport_id=None),
    ]

    def _map_devices(fn, serials):
        out = {}
        for serial in serials:
            try:
                out[serial] = fn(serial)
            except Exception as exc:  # pragma: no cover - exercised by CLI branch assertions
                out[serial] = exc
        return out

    app = types.SimpleNamespace(
        devices=types.SimpleNamespace(
            list_handles=lambda: handles,
            connect_device=lambda host: f"connected:{host}",
            authorized_serials=lambda: ["S1", "S2"],
            map_devices=_map_devices,
            info=lambda serial: types.SimpleNamespace(props={"serial": serial, "ro.product.model": "Pixel"}),
        ),
        adb=types.SimpleNamespace(shell=lambda serial, cmd, timeout_s=120.0: "line1\nline2\n"),
    )
    monkeypatch.setattr(device_cli, "console", _console())
    runner = CliRunner()

    for args in [
        ["list"],
        ["list", "--format", "json"],
        ["connect", "192.0.2.1:5555"],
        ["info", "-s", "S1"],
        ["info", "-s", "S1", "--format", "json"],
        ["info", "-s", "S1", "--all"],
        ["info", "-s", "S1", "--all", "--format", "json"],
        ["shell", "-s", "S1", "echo", "hello"],
        ["shell", "-s", "S1", "--all", "echo", "hello"],
    ]:
        result = runner.invoke(device_cli.device, args, obj=app)
        assert result.exit_code == 0, result.output

    app_with_errors = types.SimpleNamespace(
        devices=types.SimpleNamespace(
            list_handles=lambda: handles,
            connect_device=lambda host: f"connected:{host}",
            authorized_serials=lambda: ["S1", "S2"],
            map_devices=_map_devices,
            info=lambda serial: (_ for _ in ()).throw(RuntimeError("boom")) if serial == "S2" else types.SimpleNamespace(props={"serial": serial, "ro.product.model": "Pixel"}),
        ),
        adb=types.SimpleNamespace(shell=lambda serial, cmd, timeout_s=120.0: (_ for _ in ()).throw(RuntimeError("boom")) if serial == "S2" else "line1\nline2\n"),
    )
    for args in [["info", "-s", "S1", "--all"], ["shell", "-s", "S1", "--all", "echo", "hello"]]:
        result = runner.invoke(device_cli.device, args, obj=app_with_errors)
        assert result.exit_code == 0, result.output
