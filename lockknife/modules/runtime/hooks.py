from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import lru_cache
import pathlib
import re
from typing import Any


@dataclass(frozen=True)
class RuntimeScriptDescriptor:
    name: str
    file_name: str
    category: str
    title: str
    description: str
    aliases: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    default_session_kinds: tuple[str, ...] = ()


_RUNTIME_SCRIPTS = {
    "ssl_bypass": RuntimeScriptDescriptor(
        name="ssl_bypass",
        file_name="ssl_bypass.js",
        category="network",
        title="SSL pinning bypass",
        description="Bypasses common SSL/TLS certificate pinning paths including OkHttp and TrustManager hooks.",
        aliases=("ssl", "bypass_ssl", "ssl-pinning", "pinning"),
        tags=("ssl", "tls", "okhttp", "trustmanager", "flutter"),
        default_session_kinds=("bypass_ssl",),
    ),
    "root_bypass": RuntimeScriptDescriptor(
        name="root_bypass",
        file_name="root_bypass.js",
        category="evasion",
        title="Root detection bypass",
        description="Masks common root, su, Magisk, and root-management checks.",
        aliases=("root", "bypass_root", "root-detection"),
        tags=("root", "magisk", "su", "rootbeer", "safetynet"),
        default_session_kinds=("bypass_root",),
    ),
    "debug_bypass": RuntimeScriptDescriptor(
        name="debug_bypass",
        file_name="debug_bypass.js",
        category="evasion",
        title="Anti-debug bypass",
        description="Suppresses common Java and native anti-debug checks such as isDebuggerConnected and ptrace.",
        aliases=("debug", "anti_debug", "anti-debug"),
        tags=("debug", "ptrace", "tracerpid", "anti-debug"),
        default_session_kinds=("hook",),
    ),
    "crypto_intercept": RuntimeScriptDescriptor(
        name="crypto_intercept",
        file_name="crypto_intercept.js",
        category="crypto",
        title="Crypto API intercept",
        description="Intercepts Java crypto initialization and doFinal calls to surface algorithm, key, and IV context.",
        aliases=("crypto", "cipher", "crypto-hook"),
        tags=("crypto", "cipher", "key", "iv", "aes"),
        default_session_kinds=("hook", "trace"),
    ),
}


def builtin_runtime_scripts_dir() -> pathlib.Path:
    return pathlib.Path(__file__).with_name("scripts")


def builtin_runtime_script_choices() -> list[str]:
    return sorted(_RUNTIME_SCRIPTS)


def _normalize_name(value: str) -> str:
    lowered = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
    if lowered.endswith("_js"):
        lowered = lowered[:-3]
    alias_map = {
        alias: descriptor.name
        for descriptor in _RUNTIME_SCRIPTS.values()
        for alias in (descriptor.name, *descriptor.aliases)
    }
    return alias_map.get(lowered, lowered)


def _descriptor(name: str) -> RuntimeScriptDescriptor:
    normalized = _normalize_name(name)
    descriptor = _RUNTIME_SCRIPTS.get(normalized)
    if descriptor is None:
        raise ValueError(f"Unknown built-in runtime script: {name}")
    return descriptor


@lru_cache(maxsize=None)
def _script_source(name: str) -> str:
    descriptor = _descriptor(name)
    return (builtin_runtime_scripts_dir() / descriptor.file_name).read_text(encoding="utf-8")


def list_builtin_runtime_scripts() -> list[dict[str, Any]]:
    scripts: list[dict[str, Any]] = []
    for name in builtin_runtime_script_choices():
        descriptor = _descriptor(name)
        path = builtin_runtime_scripts_dir() / descriptor.file_name
        payload = asdict(descriptor)
        payload.update(
            {
                "path": str(path),
                "exists": path.exists(),
                "size_bytes": path.stat().st_size if path.exists() else 0,
            }
        )
        scripts.append(payload)
    return scripts


def get_builtin_runtime_script(name: str) -> dict[str, Any]:
    descriptor = _descriptor(name)
    path = builtin_runtime_scripts_dir() / descriptor.file_name
    return {
        **asdict(descriptor),
        "path": str(path),
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "source": _script_source(descriptor.name),
    }


def suggest_builtin_runtime_scripts(app_id: str, *, session_kind: str | None = None) -> list[dict[str, Any]]:
    app_tokens = {
        token
        for token in re.split(r"[^a-z0-9]+", app_id.lower())
        if token
    }
    weighted_tags = {
        "ssl_bypass": {"bank", "wallet", "secure", "auth", "login", "vpn", "pay"},
        "root_bypass": {"bank", "wallet", "secure", "guard", "device", "work", "mdm", "pay"},
        "debug_bypass": {"prod", "release", "protect", "secure", "bank", "wallet"},
        "crypto_intercept": {"wallet", "bank", "crypto", "vault", "pay", "auth", "secure"},
    }
    normalized_session_kind = _normalize_name(session_kind or "") if session_kind else None
    suggestions: list[dict[str, Any]] = []
    for item in list_builtin_runtime_scripts():
        score = 0
        reasons: list[str] = []
        default_session_kinds = {
            _normalize_name(value) for value in item.get("default_session_kinds") or []
        }
        if normalized_session_kind and normalized_session_kind in default_session_kinds:
            score += 5
            reasons.append(f"Aligned with session kind {session_kind}")
        tag_hits = sorted(app_tokens.intersection(weighted_tags.get(str(item["name"]), set())))
        if tag_hits:
            score += len(tag_hits) + 1
            reasons.append(f"Matched app-id hints: {', '.join(tag_hits)}")
        if not reasons and item["name"] in {"ssl_bypass", "crypto_intercept"}:
            score += 1
            reasons.append("High-value default for encrypted mobile traffic and secrets")
        if score <= 0:
            continue
        suggestions.append({**item, "score": score, "reason": "; ".join(reasons)})
    suggestions.sort(key=lambda item: (-int(item.get("score") or 0), str(item.get("title") or item.get("name") or "")))
    return suggestions[:4]


def ssl_pinning_bypass_script() -> str:
    return str(get_builtin_runtime_script("ssl_bypass")["source"])


def root_bypass_script() -> str:
    return str(get_builtin_runtime_script("root_bypass")["source"])


def debug_bypass_script() -> str:
    return str(get_builtin_runtime_script("debug_bypass")["source"])


def crypto_intercept_script() -> str:
    return str(get_builtin_runtime_script("crypto_intercept")["source"])

