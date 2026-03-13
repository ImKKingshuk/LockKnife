from __future__ import annotations

import pathlib
import shutil
import subprocess  # nosec B404
from typing import Any

from lockknife.modules.apk._decompile_archive import output_directory_overview, unpack_archive
from lockknife.modules.apk._decompile_shared import ApkError, SUPPORTED_DECOMPILE_MODES


def available_decompile_tools() -> dict[str, Any]:
    apktool = shutil.which("apktool")
    jadx = shutil.which("jadx")
    return {
        "unpack": {"available": True, "path": None},
        "apktool": {"available": bool(apktool), "path": apktool},
        "jadx": {"available": bool(jadx), "path": jadx},
    }


def selected_decompile_mode(requested_mode: str, tools: dict[str, Any]) -> str:
    if requested_mode not in SUPPORTED_DECOMPILE_MODES:
        raise ApkError(f"Unsupported decompile mode: {requested_mode}")
    if requested_mode == "auto":
        if tools["jadx"]["available"]:
            return "jadx"
        if tools["apktool"]["available"]:
            return "apktool"
        return "unpack"
    if requested_mode in {"apktool", "jadx"} and not tools[requested_mode]["available"]:
        raise ApkError(f"{requested_mode} is not available on PATH")
    if requested_mode == "hybrid":
        missing = [tool for tool in ("apktool", "jadx") if not tools[tool]["available"]]
        if missing:
            raise ApkError(f"Hybrid mode requires these tools on PATH: {', '.join(missing)}")
    return requested_mode


def run_decompile_pipeline(apk_path: pathlib.Path, output_dir: pathlib.Path, *, requested_mode: str) -> dict[str, Any]:
    tools = available_decompile_tools()
    selected_mode = selected_decompile_mode(requested_mode, tools)
    pipelines: list[dict[str, Any]] = []
    output_dirs: dict[str, str] = {}
    effective_mode = selected_mode
    fallback_applied = False
    fallback_reason: str | None = None

    def _stage(name: str, command: list[str], stage_output_dir: pathlib.Path) -> dict[str, Any]:
        return _run_external_stage(name, command, stage_output_dir)

    if selected_mode == "unpack":
        pipelines.append(unpack_archive(apk_path, output_dir))
        output_dirs["unpack"] = str(output_dir)
    elif selected_mode == "apktool":
        apktool_dir = output_dir / "apktool"
        pipelines.append(_stage("apktool", ["apktool", "d", "-f", "-o", str(apktool_dir), str(apk_path)], apktool_dir))
        output_dirs["apktool"] = str(apktool_dir)
    elif selected_mode == "jadx" and requested_mode != "auto":
        jadx_dir = output_dir / "jadx"
        pipelines.append(_stage("jadx", ["jadx", "-d", str(jadx_dir), str(apk_path)], jadx_dir))
        output_dirs["jadx"] = str(jadx_dir)
    elif selected_mode == "hybrid":
        unpack_dir = output_dir / "unpack"
        apktool_dir = output_dir / "apktool"
        jadx_dir = output_dir / "jadx"
        pipelines.append(unpack_archive(apk_path, unpack_dir))
        pipelines.append(_stage("apktool", ["apktool", "d", "-f", "-o", str(apktool_dir), str(apk_path)], apktool_dir))
        pipelines.append(_stage("jadx", ["jadx", "-d", str(jadx_dir), str(apk_path)], jadx_dir))
        output_dirs.update({"unpack": str(unpack_dir), "apktool": str(apktool_dir), "jadx": str(jadx_dir)})

    if requested_mode == "auto" and selected_mode == "jadx":
        try:
            jadx_dir = output_dir / "jadx"
            pipelines = [_stage("jadx", ["jadx", "-d", str(jadx_dir), str(apk_path)], jadx_dir)]
            output_dirs = {"jadx": str(jadx_dir)}
        except ApkError as exc:
            fallback_applied = True
            fallback_reason = str(exc)
            pipelines = []
            output_dirs = {}
            if tools["apktool"]["available"]:
                apktool_dir = output_dir / "apktool"
                pipelines.append(_stage("apktool", ["apktool", "d", "-f", "-o", str(apktool_dir), str(apk_path)], apktool_dir))
                output_dirs["apktool"] = str(apktool_dir)
                effective_mode = "apktool"
            else:
                pipelines.append(unpack_archive(apk_path, output_dir))
                output_dirs["unpack"] = str(output_dir)
                effective_mode = "unpack"

    source_inventory = _build_source_inventory(output_dir, output_dirs, effective_mode)
    return {
        "requested_mode": requested_mode,
        "selected_mode": selected_mode,
        "effective_mode": effective_mode,
        "fallback_applied": fallback_applied,
        "fallback_reason": fallback_reason,
        "pipelines": pipelines,
        "positioning": decompile_positioning(effective_mode, tools),
        "decompilation_depth": _decompilation_depth(effective_mode),
        "tooling": tools,
        "decompile_outputs": output_dirs,
        "source_inventory": source_inventory,
    }


def decompile_positioning(selected_mode: str, tools: dict[str, Any]) -> dict[str, Any]:
    level_map = {
        "unpack": (
            "archive-unpack",
            "Low",
            "Archive extraction plus manifest, signing, and string/code-signal analysis; not source recovery.",
            "Run analyze or vulnerability next if you need scored findings without source output.",
        ),
        "apktool": (
            "decoded-resources",
            "Medium",
            "apktool decodes resources and manifest structure for manual review.",
            "Review Android resources, smali, and manifest overlays from the apktool directory.",
        ),
        "jadx": (
            "java-like-source",
            "High",
            "jadx produces Java-like source views for reverse-engineering workflows.",
            "Start with jadx source for class triage, then pivot back to raw archive evidence when needed.",
        ),
        "hybrid": (
            "hybrid",
            "High",
            "Hybrid mode keeps raw extraction plus apktool and jadx outputs together.",
            "Use JADX for source review and apktool/unpack output when resource or byte-level verification matters.",
        ),
    }
    level, confidence, summary, recommended_next = level_map[selected_mode]
    return {
        "selected_mode": selected_mode,
        "source_recovery_level": level,
        "operator_confidence": confidence,
        "summary": summary,
        "recommended_next": recommended_next,
        "tool_visibility": tools,
    }


def _run_external_stage(name: str, command: list[str], output_dir: pathlib.Path) -> dict[str, Any]:
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)  # nosec B603
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise ApkError(stderr or f"decompile pipeline failed: {' '.join(command)}") from exc
    return {
        "name": name,
        "status": "completed",
        "output_dir": str(output_dir),
        **output_directory_overview(output_dir),
    }


def _build_source_inventory(output_dir: pathlib.Path, output_dirs: dict[str, str], effective_mode: str) -> dict[str, Any]:
    scan_root = pathlib.Path(output_dirs.get("jadx") or output_dirs.get("apktool") or output_dirs.get("unpack") or output_dir)
    if not scan_root.exists():
        return {"root": str(scan_root), "file_count": 0, "java_like_count": 0, "interesting_files": []}
    interesting_suffixes = {".java", ".kt", ".smali", ".xml", ".json"}
    counts = {"java": 0, "kt": 0, "smali": 0, "xml": 0, "json": 0}
    interesting_files: list[str] = []
    total_files = 0
    for path in scan_root.rglob("*"):
        if not path.is_file():
            continue
        total_files += 1
        suffix = path.suffix.lower()
        if suffix in interesting_suffixes and len(interesting_files) < 25:
            interesting_files.append(str(path.relative_to(scan_root)))
        if suffix == ".java":
            counts["java"] += 1
        elif suffix == ".kt":
            counts["kt"] += 1
        elif suffix == ".smali":
            counts["smali"] += 1
        elif suffix == ".xml":
            counts["xml"] += 1
        elif suffix == ".json":
            counts["json"] += 1
    return {
        "root": str(scan_root),
        "effective_mode": effective_mode,
        "file_count": total_files,
        "java_like_count": counts["java"] + counts["kt"],
        "counts": counts,
        "interesting_files": interesting_files,
    }


def _decompilation_depth(selected_mode: str) -> dict[str, Any]:
    depth_map = {
        "unpack": {"level": "low", "source_indexed": False, "jadx_available": False},
        "apktool": {"level": "medium", "source_indexed": False, "jadx_available": False},
        "jadx": {"level": "high", "source_indexed": True, "jadx_available": True},
        "hybrid": {"level": "high", "source_indexed": True, "jadx_available": True},
    }
    payload = dict(depth_map[selected_mode])
    payload["selected_mode"] = selected_mode
    payload["reconstructed_sources"] = selected_mode in {"jadx", "hybrid"}
    payload["decoded_resources"] = selected_mode in {"apktool", "hybrid"}
    payload["archive_unpacked"] = selected_mode in {"unpack", "hybrid"}
    return payload
