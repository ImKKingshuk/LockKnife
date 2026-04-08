from __future__ import annotations

import importlib
import json
import shutil
import sys
from typing import Any

from lockknife.core.adb import AdbClient
from lockknife.core.config import load_config
from lockknife.core.exceptions import LockKnifeError
from lockknife.core.plugin_loader import plugin_health_summary
from lockknife.core.secrets import load_secrets


def _check_module(module_name: str, *, hint: str | None = None) -> dict[str, Any]:
    try:
        importlib.import_module(module_name)
        return {"ok": True, "module": module_name}
    except Exception as e:
        payload: dict[str, Any] = {"ok": False, "module": module_name, "error": str(e)}
        if hint:
            payload["hint"] = hint
        return payload


def _configured_secret(name: str, value: str | None, *, hint: str | None = None) -> dict[str, Any]:
    ok = bool(value and value.strip())
    payload: dict[str, Any] = {"ok": ok, "name": name, "configured": ok}
    if hint and not ok:
        payload["hint"] = hint
    return payload


def health_status() -> dict[str, Any]:
    checks: dict[str, Any] = {}
    ok = True

    cfg = None
    try:
        cfg = load_config()
        checks["config"] = {"ok": True, "path": str(cfg.path) if cfg.path else None}
    except LockKnifeError as e:
        ok = False
        checks["config"] = {
            "ok": False,
            "error": str(e),
            "hint": "Create a valid lockknife.toml or point LockKnife at the correct config file before re-running diagnostics.",
        }

    try:
        adb_path = None
        if cfg is not None:
            adb_path = cfg.config.adb_path or "adb"
        resolved_adb = shutil.which(adb_path or "adb") or adb_path or "adb"
        if shutil.which(resolved_adb) is None and resolved_adb == (adb_path or "adb"):
            raise RuntimeError(f"adb not found: {resolved_adb}")
        adb = AdbClient(resolved_adb)
        adb.run(["version"], timeout_s=5.0)
        checks["adb"] = {"ok": True, "path": adb.adb_path}
    except Exception as e:
        ok = False
        checks["adb"] = {
            "ok": False,
            "error": str(e),
            "hint": "Install adb or set adb_path in lockknife.toml so device-backed workflows can run.",
        }

    try:
        import lockknife.lockknife_core as _core

        checks["rust_extension"] = {"ok": True, "version": getattr(_core, "__version__", None)}
    except Exception as e:
        ok = False
        checks["rust_extension"] = {
            "ok": False,
            "error": str(e),
            "hint": "Reinstall LockKnife so the native Rust extension is available for this Python environment.",
        }

    plugins = plugin_health_summary()
    checks["plugins"] = plugins
    ok = bool(ok and plugins.get("ok"))

    return {"ok": ok, "checks": checks}


def doctor_status() -> dict[str, Any]:
    core = health_status()
    secrets = load_secrets()
    rust_ok = bool((core.get("checks") or {}).get("rust_extension", {}).get("ok"))

    apk = _check_module(
        "androguard.core.bytecodes.apk", hint="Install APK support extras: uv sync --extra apk"
    )
    apktool = shutil.which("apktool")
    jadx = shutil.which("jadx")
    frida = _check_module("frida", hint="Install runtime extras: uv sync --extra frida")
    scapy = _check_module("scapy", hint="Install network extras: uv sync --extra network")
    vt_mod = _check_module("vt", hint="Install threat intel extras: uv sync --extra threat-intel")
    otx_mod = _check_module(
        "OTXv2", hint="Install threat intel extras: uv sync --extra threat-intel"
    )
    yara_py = _check_module("yara", hint="Install YARA support: uv sync --extra yara")
    numpy_mod = _check_module("numpy", hint="Install ML extras: uv sync --extra ml")
    sklearn_mod = _check_module("sklearn", hint="Install ML extras: uv sync --extra ml")
    joblib_mod = _check_module("joblib", hint="Install ML extras: uv sync --extra ml")
    weasy_mod = _check_module("weasyprint")
    xhtml_mod = _check_module("xhtml2pdf")

    pdf_ok = bool(weasy_mod.get("ok") or xhtml_mod.get("ok"))
    ai_ok = bool(numpy_mod.get("ok") and sklearn_mod.get("ok") and joblib_mod.get("ok"))
    vt_key = _configured_secret(
        "VT_API_KEY", secrets.VT_API_KEY, hint="Set VT_API_KEY in the environment or .env"
    )
    otx_key = _configured_secret(
        "OTX_API_KEY", secrets.OTX_API_KEY, hint="Set OTX_API_KEY in the environment or .env"
    )

    optional: dict[str, Any] = {
        "apk_analysis": apk,
        "apk_decompile_tools": {
            "ok": bool(apktool or jadx),
            "apktool": {"ok": bool(apktool), "path": apktool},
            "jadx": {"ok": bool(jadx), "path": jadx},
            "hint": "Install apktool and/or jadx to upgrade decompile workflows beyond raw archive unpacking.",
        },
        "runtime_frida": frida,
        "network_analysis": scapy,
        "malware_scanning": {
            "ok": bool(rust_ok or yara_py.get("ok")),
            "rust_extension": rust_ok,
            "yara_python": yara_py,
            "hint": "Rust core enables yara-x scanning; yara-python is an optional fallback.",
        },
        "pdf_generation": {
            "ok": pdf_ok,
            "backends": {"weasyprint": weasy_mod, "xhtml2pdf": xhtml_mod},
            "hint": "Install weasyprint or xhtml2pdf for PDF report output."
            if not pdf_ok
            else None,
        },
        "ai_ml": {
            "ok": ai_ok,
            "modules": {"numpy": numpy_mod, "sklearn": sklearn_mod, "joblib": joblib_mod},
            "hint": "Install ML extras: uv sync --extra ml" if not ai_ok else None,
        },
        "virustotal": {
            "ok": bool(vt_mod.get("ok") and vt_key.get("configured")),
            "installed": bool(vt_mod.get("ok")),
            "configured": bool(vt_key.get("configured")),
            "module": vt_mod,
            "secret": vt_key,
            "hint": "Requires vt-py plus VT_API_KEY.",
        },
        "otx": {
            "ok": bool(otx_mod.get("ok") and otx_key.get("configured")),
            "installed": bool(otx_mod.get("ok")),
            "configured": bool(otx_key.get("configured")),
            "module": otx_mod,
            "secret": otx_key,
            "hint": "Requires OTXv2 plus OTX_API_KEY.",
        },
    }

    full_ok = bool(core.get("ok") and all(bool(item.get("ok")) for item in optional.values()))
    return {
        "ok": bool(core.get("ok")),
        "full_ok": full_ok,
        "python": sys.version.split()[0],
        "checks": core.get("checks", {}),
        "optional": optional,
    }


def _main() -> int:
    payload = health_status()
    print(json.dumps(payload))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(_main())
