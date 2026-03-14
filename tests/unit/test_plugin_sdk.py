import sys
from types import SimpleNamespace

from click.testing import CliRunner


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