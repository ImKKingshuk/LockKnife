import pathlib
import sys
from types import SimpleNamespace

from click.testing import CliRunner


ROOT = pathlib.Path(__file__).resolve().parents[2]
EXAMPLE_PLUGIN_SRC = ROOT / "examples" / "plugins" / "lockknife_example_plugin" / "src"


def _enable_example_plugin(monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(EXAMPLE_PLUGIN_SRC))
    monkeypatch.setenv("LOCKKNIFE_PLUGIN_MODULES", "lockknife_example_plugin.plugin:get_plugin")


def _add_example_plugin_path(monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(EXAMPLE_PLUGIN_SRC))


def test_plugin_inventory_loads_example_plugin_from_env(monkeypatch) -> None:
    from lockknife.core import plugin_loader

    _enable_example_plugin(monkeypatch)
    plugin_loader.reset_plugin_manager()

    payload = plugin_loader.plugin_inventory(reload=True)
    loaded = payload["loaded"]
    assert len(loaded) == 1
    assert loaded[0]["metadata"]["name"] == "example-hello"
    assert loaded[0]["commands"] == ["hello-plugin"]
    assert loaded[0]["capabilities"][0]["cli"] == "lockknife --cli hello-plugin"


def test_plugin_inventory_loads_entry_points_and_reports_incompatible_plugins(monkeypatch) -> None:
    from lockknife.core import plugin_loader
    from lockknife.core.plugin_contract import LOCKKNIFE_PLUGIN_API_VERSION, LockKnifePlugin
    from lockknife.core.plugin_models import PluginMetadata

    _enable_example_plugin(monkeypatch)

    class _FakeEntryPoint:
        def __init__(self, name, value):
            self.name = name
            self.value = name
            self._value = value

        def load(self):
            return self._value

    class _BadPlugin(LockKnifePlugin):
        metadata = PluginMetadata(name="bad-plugin", version="0.0.1", api_version=str(int(LOCKKNIFE_PLUGIN_API_VERSION) + 1))

        def register(self, registry):
            _ = registry

    monkeypatch.setattr(
        plugin_loader,
        "entry_points",
        lambda: {
            "lockknife.plugins": [
                _FakeEntryPoint("ep-example", __import__("lockknife_example_plugin.plugin", fromlist=["get_plugin"]).get_plugin),
                _FakeEntryPoint("bad", _BadPlugin),
            ]
        },
    )
    plugin_loader.reset_plugin_manager()

    payload = plugin_loader.plugin_inventory(reload=True)
    assert any(item["source"] == "entry-point:ep-example" for item in payload["loaded"])
    assert any("plugin API mismatch" in item["error"] for item in payload["failures"])


def test_cli_can_invoke_plugin_command_and_list_inventory(monkeypatch) -> None:
    from lockknife_headless_cli import main as main_cli
    from lockknife.core.config import LoadedConfig, LockKnifeConfig
    from lockknife.core.plugin_loader import reset_plugin_manager

    _enable_example_plugin(monkeypatch)
    reset_plugin_manager()
    monkeypatch.setattr(main_cli, "load_config", lambda: LoadedConfig(config=LockKnifeConfig(), path=None))
    monkeypatch.setattr(main_cli, "configure_logging", lambda *_a, **_k: None)
    monkeypatch.setattr(main_cli, "import_submodules", lambda *_a, **_k: None)
    monkeypatch.setattr(main_cli, "load_registered_modules", lambda: None)
    monkeypatch.setattr(main_cli.signal, "signal", lambda *_a, **_k: None)

    runner = CliRunner()
    command = runner.invoke(main_cli.cli, ["--cli", "hello-plugin", "--name", "Ada"])
    assert command.exit_code == 0, command.output
    assert '"message": "hello Ada"' in command.output

    listing = runner.invoke(main_cli.cli, ["--cli", "plugins", "list", "--format", "json", "--reload"])
    assert listing.exit_code == 0, listing.output
    assert '"name": "example-hello"' in listing.output

    text_listing = runner.invoke(main_cli.cli, ["--cli", "plugins", "list", "--reload"])
    assert text_listing.exit_code == 0, text_listing.output
    assert "Plugin API version:" in text_listing.output
    assert "example-hello" in text_listing.output


def test_plugins_group_renders_text_inventory(monkeypatch) -> None:
    from lockknife_headless_cli import plugins as plugins_cli
    from lockknife.core.plugin_loader import reset_plugin_manager

    class _Console:
        def __init__(self) -> None:
            self.buffer: list[str] = []

        def print(self, message: object) -> None:
            self.buffer.append(str(message))

        def print_json(self, message: str) -> None:
            self.buffer.append(message)

    _enable_example_plugin(monkeypatch)
    reset_plugin_manager()
    fake_console = _Console()
    monkeypatch.setattr(plugins_cli, "console", fake_console)

    result = CliRunner().invoke(plugins_cli.plugins_group, ["list", "--reload"])
    assert result.exit_code == 0, result.output
    rendered = "\n".join(fake_console.buffer)
    assert "Loaded plugins: 1" in rendered
    assert "example-hello" in rendered


def test_plugin_text_renderer_handles_non_list_payloads() -> None:
    from lockknife_headless_cli.plugins import _render_text

    rendered = _render_text({"api_version": "1", "loaded": "invalid", "failures": None})
    assert "Plugin API version: 1" in rendered
    assert "Loaded plugins: 0" in rendered
    assert "Failed plugins: 0" in rendered


def test_health_status_includes_plugin_summary(monkeypatch) -> None:
    import lockknife.core.health as health_mod

    class _Adb:
        def __init__(self, adb_path: str) -> None:
            self.adb_path = adb_path

        def run(self, *_a, **_k) -> str:
            return "ok"

    monkeypatch.setattr(health_mod, "load_config", lambda: SimpleNamespace(config=SimpleNamespace(adb_path="adb"), path=None))
    monkeypatch.setattr(health_mod, "AdbClient", _Adb)
    monkeypatch.setattr(health_mod.shutil, "which", lambda _name: "/usr/bin/adb")
    monkeypatch.setattr(health_mod, "plugin_health_summary", lambda: {"ok": False, "loaded": 1, "failed": 1})
    monkeypatch.setitem(sys.modules, "lockknife.lockknife_core", SimpleNamespace(__version__="1.0.0"))

    payload = health_mod.health_status()
    assert payload["ok"] is False
    assert payload["checks"]["plugins"]["failed"] == 1