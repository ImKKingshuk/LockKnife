from __future__ import annotations

import importlib
import json
import os
import pathlib
import shutil
import sys
from typing import Any

from lockknife.core.adb import AdbClient, resolve_adb_binary
from lockknife.core.config import load_config
from lockknife.core.exceptions import LockKnifeError
from lockknife.core.plugin_loader import plugin_health_summary
from lockknife.core.secrets import load_secrets


def resolve_tool_binary(tool_name: str) -> str | None:
    """Find an external binary on PATH or in standard user/system install locations."""
    found = shutil.which(tool_name)
    if found:
        return found
    try:
        home = pathlib.Path.home()
        candidates = [
            pathlib.Path("/opt/homebrew/bin") / tool_name,
            pathlib.Path("/usr/local/bin") / tool_name,
            pathlib.Path("/usr/bin") / tool_name,
            home / ".local" / "bin" / tool_name,
            pathlib.Path(f"/opt/{tool_name}/bin") / tool_name,
        ]
        for c in candidates:
            if c.is_file() and os.access(c, os.X_OK):
                return str(c)
    except Exception:
        pass
    return None

EXTRA_REQUIREMENTS: dict[str, list[str]] = {
    "apk": ["androguard>=4.1.4"],
    "frida": ["frida-tools>=14.10.4"],
    "ml": ["scikit-learn>=1.9.1", "numpy>=2.5.3", "joblib>=1.6.0"],
    "yara": ["yara-python>=4.3"],
    "threat-intel": ["vt-py>=0.18", "OTXv2>=1.5"],
    "network": ["scapy>=2.8.0"],
    "pdf": ["xhtml2pdf>=0.2.15"],
}


def get_fallback_site_packages() -> list[str]:
    """Find user and system site-packages directories that may contain installed packages."""
    candidates: list[str] = []

    # 1. User site-packages (often disabled in isolated virtual environments)
    try:
        import site

        if hasattr(site, "getusersitepackages"):
            user_site = site.getusersitepackages()
            if isinstance(user_site, str) and user_site not in candidates:
                candidates.append(user_site)
    except Exception:
        pass

    # 2. Base prefix site-packages (when running inside a venv)
    try:
        base_prefix = getattr(sys, "base_prefix", sys.prefix)
        if base_prefix and base_prefix != sys.prefix:
            py_ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
            base_site = str(pathlib.Path(base_prefix) / "lib" / py_ver / "site-packages")
            base_dist = str(pathlib.Path(base_prefix) / "lib" / py_ver / "dist-packages")
            for p in (base_site, base_dist):
                if p not in candidates:
                    candidates.append(p)
    except Exception:
        pass

    # 3. Standard Linux / Unix dist-packages and site-packages (Debian/Ubuntu/Kali)
    py_ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    system_paths = [
        "/usr/lib/python3/dist-packages",
        f"/usr/lib/{py_ver}/dist-packages",
        f"/usr/local/lib/{py_ver}/dist-packages",
        f"/usr/lib/{py_ver}/site-packages",
        f"/usr/local/lib/{py_ver}/site-packages",
    ]
    for p in system_paths:
        if p not in candidates:
            candidates.append(p)

    return [p for p in candidates if pathlib.Path(p).is_dir()]


def enable_fallback_site_packages() -> list[str]:
    """Add existing fallback site-packages to sys.path if not already present."""
    added: list[str] = []
    for p in get_fallback_site_packages():
        if p not in sys.path:
            sys.path.append(p)
            added.append(p)
    return added


def _check_module(
    module_name: str,
    *,
    extra: str | None = None,
    hint: str | None = None,
) -> dict[str, Any]:
    py_exe = sys.executable or "python"
    fallback_hint = (
        hint
        if hint
        else (
            f"Install with: {py_exe} -m pip install 'lockknife[{extra}]' (or run: lockknife doctor --install-missing)"
            if extra
            else f"Install with: {py_exe} -m pip install {module_name}"
        )
    )

    try:
        mod = importlib.import_module(module_name)
        source = getattr(mod, "__file__", None)
        return {
            "ok": True,
            "module": module_name,
            "source": str(source) if source else None,
            **({"extra": extra} if extra else {}),
        }
    except Exception as first_exc:
        # Check if loading from fallback site-packages succeeds
        added = enable_fallback_site_packages()
        if added:
            try:
                mod = importlib.import_module(module_name)
                source = getattr(mod, "__file__", None)
                return {
                    "ok": True,
                    "module": module_name,
                    "source": str(source) if source else None,
                    "loaded_from_fallback": True,
                    **({"extra": extra} if extra else {}),
                }
            except Exception:
                pass

        # Inspect if files exist in fallback paths on disk
        pkg_base = module_name.split(".")[0]
        disk_candidates = [
            p
            for p in get_fallback_site_packages()
            if (pathlib.Path(p) / pkg_base).exists()
            or (pathlib.Path(p) / f"{pkg_base}.py").exists()
            or any(pathlib.Path(p).glob(f"{pkg_base}-*.dist-info"))
        ]

        if disk_candidates:
            err_msg = (
                f"{first_exc} (Found on disk in {disk_candidates[0]}, but cannot be imported into "
                f"active python {sys.executable} due to environment isolation or incompatibility)"
            )
        else:
            err_msg = str(first_exc)

        payload: dict[str, Any] = {
            "ok": False,
            "module": module_name,
            "error": err_msg,
            "hint": fallback_hint,
        }
        if extra:
            payload["extra"] = extra
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
        resolved_adb = resolve_adb_binary(adb_path or "adb")
        if shutil.which(resolved_adb) is None and not pathlib.Path(resolved_adb).is_file():
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

    apk = _check_module("androguard.core.apk", extra="apk")
    if not apk["ok"]:
        apk = _check_module("androguard.core.bytecodes.apk", extra="apk")
    apktool = resolve_tool_binary("apktool")
    jadx = resolve_tool_binary("jadx")
    frida = _check_module("frida", extra="frida")
    scapy = _check_module("scapy", extra="network")
    vt_mod = _check_module("vt", extra="threat-intel")
    otx_mod = _check_module("OTXv2", extra="threat-intel")
    yara_py = _check_module("yara", extra="yara")
    numpy_mod = _check_module("numpy", extra="ml")
    sklearn_mod = _check_module("sklearn", extra="ml")
    joblib_mod = _check_module("joblib", extra="ml")
    weasy_mod = _check_module("weasyprint", extra="pdf")
    xhtml_mod = _check_module("xhtml2pdf", extra="pdf")

    pdf_ok = bool(weasy_mod.get("ok") or xhtml_mod.get("ok"))
    ai_ok = bool(numpy_mod.get("ok") and sklearn_mod.get("ok") and joblib_mod.get("ok"))
    vt_key = _configured_secret(
        "VT_API_KEY", secrets.VT_API_KEY, hint="Set VT_API_KEY in the environment or .env"
    )
    otx_key = _configured_secret(
        "OTX_API_KEY", secrets.OTX_API_KEY, hint="Set OTX_API_KEY in the environment or .env"
    )

    py_exe = sys.executable or "python"
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
            "ok": bool(yara_py.get("ok")),
            "yara_python": yara_py,
            "extra": "yara",
            "hint": (
                "Install the yara extra to enable malware rule scanning: "
                f"{py_exe} -m pip install 'lockknife[yara]'"
            )
            if not yara_py.get("ok")
            else None,
        },
        "pdf_generation": {
            "ok": pdf_ok,
            "backends": {"weasyprint": weasy_mod, "xhtml2pdf": xhtml_mod},
            "extra": "pdf",
            "hint": (
                "Install weasyprint or xhtml2pdf for PDF report output: "
                f"{py_exe} -m pip install 'lockknife[pdf]'"
            )
            if not pdf_ok
            else None,
        },
        "ai_ml": {
            "ok": ai_ok,
            "modules": {"numpy": numpy_mod, "sklearn": sklearn_mod, "joblib": joblib_mod},
            "extra": "ml",
            "hint": (
                "Install ML extras to enable machine-learning detection: "
                f"{py_exe} -m pip install 'lockknife[ml]'"
            )
            if not ai_ok
            else None,
        },
        "virustotal": {
            "ok": bool(vt_mod.get("ok") and vt_key.get("configured")),
            "installed": bool(vt_mod.get("ok")),
            "configured": bool(vt_key.get("configured")),
            "module": vt_mod,
            "secret": vt_key,
            "extra": "threat-intel",
            "hint": "Requires vt-py plus VT_API_KEY.",
        },
        "otx": {
            "ok": bool(otx_mod.get("ok") and otx_key.get("configured")),
            "installed": bool(otx_mod.get("ok")),
            "configured": bool(otx_key.get("configured")),
            "module": otx_mod,
            "secret": otx_key,
            "extra": "threat-intel",
            "hint": "Requires OTXv2 plus OTX_API_KEY.",
        },
    }

    env_info = {
        "python_executable": sys.executable,
        "python_version": sys.version.split()[0],
        "is_venv": sys.prefix != getattr(sys, "base_prefix", sys.prefix),
        "prefix": sys.prefix,
        "base_prefix": getattr(sys, "base_prefix", sys.prefix),
        "fallback_paths": get_fallback_site_packages(),
    }

    full_ok = bool(core.get("ok") and all(bool(item.get("ok")) for item in optional.values()))
    return {
        "ok": bool(core.get("ok")),
        "full_ok": full_ok,
        "python": sys.version.split()[0],
        "environment": env_info,
        "checks": core.get("checks", {}),
        "optional": optional,
    }


def install_missing_dependencies(
    extras: list[str] | None = None,
    *,
    all_extras: bool = False,
    dry_run: bool = False,
    pip_args: list[str] | None = None,
) -> dict[str, Any]:
    """Automated dependencies installer for missing or selected LockKnife extras."""
    doc = doctor_status()
    target_extras: list[str] = []

    if all_extras:
        target_extras = sorted(EXTRA_REQUIREMENTS.keys())
    elif extras:
        target_extras = [e for e in extras if e in EXTRA_REQUIREMENTS]
    else:
        detected: set[str] = set()
        optional = doc.get("optional", {})
        for item in optional.values():
            if isinstance(item, dict) and not item.get("ok"):
                ext = item.get("extra")
                if ext and ext in EXTRA_REQUIREMENTS:
                    detected.add(ext)
                for sub in ("modules", "backends", "yara_python"):
                    sub_val = item.get(sub)
                    if isinstance(sub_val, dict):
                        if not sub_val.get("ok") and sub_val.get("extra"):
                            detected.add(sub_val["extra"])
                        elif isinstance(sub_val, dict):
                            for mod_data in sub_val.values():
                                if (
                                    isinstance(mod_data, dict)
                                    and not mod_data.get("ok")
                                    and mod_data.get("extra")
                                ):
                                    detected.add(mod_data["extra"])
        target_extras = sorted(detected)

    if not target_extras:
        return {
            "ok": True,
            "target_extras": [],
            "packages": [],
            "installed": False,
            "message": "All optional dependencies are already satisfied.",
        }

    packages_to_install: list[str] = []
    for ext in target_extras:
        packages_to_install.extend(EXTRA_REQUIREMENTS.get(ext, []))

    py_exe = sys.executable or "python"
    cmd = [py_exe, "-m", "pip", "install", *packages_to_install]
    if pip_args:
        cmd.extend(pip_args)

    if dry_run:
        return {
            "ok": True,
            "target_extras": target_extras,
            "packages": packages_to_install,
            "command": cmd,
            "command_str": " ".join(cmd),
            "dry_run": True,
            "installed": False,
            "message": f"Dry-run: command to install {target_extras}: {' '.join(cmd)}",
        }

    try:
        import subprocess

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        return {
            "ok": res.returncode == 0,
            "target_extras": target_extras,
            "packages": packages_to_install,
            "command": cmd,
            "command_str": " ".join(cmd),
            "exit_code": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "installed": res.returncode == 0,
            "message": (
                f"Successfully installed dependencies for extras: {', '.join(target_extras)}"
                if res.returncode == 0
                else f"Failed to install dependencies (exit code {res.returncode}): {res.stderr.strip()}"
            ),
        }
    except Exception as exc:
        return {
            "ok": False,
            "target_extras": target_extras,
            "packages": packages_to_install,
            "command": cmd,
            "command_str": " ".join(cmd),
            "error": str(exc),
            "installed": False,
            "message": f"Installation failed with error: {exc}",
        }


def _main() -> int:
    payload = health_status()
    print(json.dumps(payload))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(_main())

