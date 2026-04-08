import types


def test_health_status_ok(monkeypatch) -> None:
    from lockknife.core import health as health_mod

    class _Cfg:
        def __init__(self) -> None:
            self.path = None
            self.config = types.SimpleNamespace(adb_path="adb")

    monkeypatch.setattr(health_mod, "load_config", lambda: _Cfg())
    monkeypatch.setattr(health_mod.shutil, "which", lambda _value: "/usr/bin/adb")

    class _Adb:
        def __init__(self, adb_path: str) -> None:
            self.adb_path = adb_path

        def run(self, *args, **kwargs):
            return "ok"

    monkeypatch.setattr(health_mod, "AdbClient", _Adb)
    monkeypatch.setitem(
        __import__("sys").modules,
        "lockknife.lockknife_core",
        types.SimpleNamespace(__version__="x"),
    )

    out = health_mod.health_status()
    assert out["ok"] is True
    assert out["checks"]["adb"]["ok"] is True
    assert out["checks"]["rust_extension"]["ok"] is True


def test_health_status_reports_errors(monkeypatch) -> None:
    from lockknife.core import health as health_mod
    from lockknife.core.exceptions import LockKnifeError

    def boom():
        raise LockKnifeError("bad")

    monkeypatch.setattr(health_mod, "load_config", boom)
    monkeypatch.setattr(health_mod.shutil, "which", lambda _value: None)
    monkeypatch.setattr(
        health_mod, "AdbClient", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("no adb"))
    )
    monkeypatch.setitem(__import__("sys").modules, "lockknife.lockknife_core", None)

    out = health_mod.health_status()
    assert out["ok"] is False
    assert out["checks"]["config"]["ok"] is False
    assert "hint" in out["checks"]["config"]
    assert out["checks"]["adb"]["ok"] is False
    assert "hint" in out["checks"]["adb"]
    assert out["checks"]["rust_extension"]["ok"] is False
    assert "hint" in out["checks"]["rust_extension"]


def test_doctor_status_includes_optional_checks(monkeypatch) -> None:
    from lockknife.core import health as health_mod

    monkeypatch.setattr(
        health_mod,
        "health_status",
        lambda: {"ok": True, "checks": {"rust_extension": {"ok": True}, "adb": {"ok": True}}},
    )
    monkeypatch.setattr(
        health_mod,
        "load_secrets",
        lambda: types.SimpleNamespace(VT_API_KEY="vt-key", OTX_API_KEY=None),
    )

    def fake_import(name: str):
        if name in {
            "androguard.core.bytecodes.apk",
            "frida",
            "scapy",
            "vt",
            "numpy",
            "sklearn",
            "joblib",
            "weasyprint",
        }:
            return object()
        raise ImportError(name)

    monkeypatch.setattr(health_mod.importlib, "import_module", fake_import)
    monkeypatch.setattr(
        health_mod.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in {"apktool", "jadx"} else None,
    )

    out = health_mod.doctor_status()
    assert out["ok"] is True
    assert out["optional"]["apk_analysis"]["ok"] is True
    assert out["optional"]["apk_decompile_tools"]["ok"] is True
    assert out["optional"]["apk_decompile_tools"]["apktool"]["ok"] is True
    assert out["optional"]["virustotal"]["ok"] is True
    assert out["optional"]["otx"]["ok"] is False
    assert out["full_ok"] is False
