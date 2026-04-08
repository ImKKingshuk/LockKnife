from __future__ import annotations

import pathlib
import zipfile
from typing import Any

from lockknife.modules.apk._decompile_inspection import _redact_secret, _string_preview
from lockknife.modules.apk._decompile_shared import (
    ASCII_STRING_RE,
    CERT_PIN_RE,
    HOST_HINT_RE,
    SECRET_INDICATOR_RE,
    TEXT_FILE_SUFFIXES,
    URL_RE,
)

_LIBRARY_PATTERNS = (
    ("okhttp", "OkHttp", "network", ("okhttp3", "okhttp/", "okhttpclient")),
    ("retrofit", "Retrofit", "network", ("retrofit2", "retrofit/")),
    ("firebase", "Firebase", "platform", ("firebase", "google.firebase")),
    (
        "play-services",
        "Google Play Services",
        "platform",
        ("com.google.android.gms", "play-services"),
    ),
    ("webview", "Android WebView", "web", ("android.webkit", "webview")),
    ("sentry", "Sentry", "telemetry", ("io.sentry", "sentry")),
    ("bugsnag", "Bugsnag", "telemetry", ("bugsnag",)),
    ("rootbeer", "RootBeer", "resilience", ("rootbeer",)),
)

_TRACKER_PATTERNS = (
    (
        "firebase-analytics",
        "Firebase Analytics",
        "analytics",
        ("firebaseanalytics", "google.firebase.analytics"),
    ),
    ("appsflyer", "AppsFlyer", "attribution", ("appsflyer",)),
    ("adjust", "Adjust", "attribution", ("com.adjust", "adjustsdk")),
    ("mixpanel", "Mixpanel", "analytics", ("mixpanel",)),
    ("amplitude", "Amplitude", "analytics", ("amplitude",)),
    ("segment", "Segment", "analytics", ("segmentio", "analytics-android")),
    ("onesignal", "OneSignal", "messaging", ("onesignal",)),
    ("branch", "Branch", "deeplink-attribution", ("io.branch", "branch.io")),
)

_CODE_SIGNAL_PATTERNS = (
    (
        "dynamic-code-loading",
        "Dynamic code loading APIs",
        "medium",
        "Source or string markers reference DexClassLoader or similar dynamic loading APIs.",
        ("dexclassloader", "pathclassloader", "inmemorydexclassloader"),
    ),
    (
        "webview-js-bridge",
        "WebView JavaScript bridge",
        "medium",
        "The archive references addJavascriptInterface-style bridging between Java/Kotlin and web content.",
        ("addjavascriptinterface",),
    ),
    (
        "frida-detection",
        "Frida detection indicators",
        "low",
        "Strings suggest the app checks for Frida, gum, or instrumentation tooling.",
        ("frida", "gum-js-loop", "gum-js-loop", "re.frida.server"),
    ),
    (
        "root-detection",
        "Root detection indicators",
        "low",
        "Strings suggest checks for su, Magisk, RootBeer, or similar root-detection logic.",
        ("magisk", "busybox", "supersu", "test-keys", "rootbeer", "which su"),
    ),
    (
        "insecure-storage-world-readable",
        "World-readable storage APIs",
        "high",
        "Source or strings reference deprecated MODE_WORLD_READABLE / MODE_WORLD_WRITABLE style storage flags.",
        ("mode_world_readable", "mode_world_writable", "world_readable", "world_writable"),
    ),
    (
        "crypto-ecb-mode",
        "ECB cryptography mode",
        "high",
        "Strings reference AES/ECB or similar ECB-mode cryptography usage that weakens confidentiality.",
        ("aes/ecb", "/ecb/", "ecb/pkcs5padding", "ecb/nopadding"),
    ),
    (
        "crypto-static-iv",
        "Static IV cryptography",
        "high",
        "Strings suggest IV reuse or hard-coded IV byte arrays in symmetric cryptography paths.",
        ("ivparameterspec(new byte", "static iv", "fixed iv", "0000000000000000"),
    ),
)


def scan_archive_code_signals(apk_path: pathlib.Path) -> dict[str, Any]:
    urls: list[dict[str, str]] = []
    direct_hosts: list[dict[str, str]] = []
    secrets: list[dict[str, str]] = []
    pins: list[dict[str, str]] = []
    scanned_files: list[str] = []
    libraries = _match_registry(_LIBRARY_PATTERNS)
    trackers = _match_registry(_TRACKER_PATTERNS)
    signals = _signal_registry(_CODE_SIGNAL_PATTERNS)
    seen_urls: set[tuple[str, str]] = set()
    seen_hosts: set[tuple[str, str]] = set()
    seen_secrets: set[tuple[str, str]] = set()
    seen_pins: set[tuple[str, str]] = set()
    native_libraries: list[dict[str, Any]] = []

    with zipfile.ZipFile(apk_path, "r") as archive:
        for name in _candidate_names(archive.namelist()):
            try:
                raw = archive.read(name)
            except (KeyError, OSError, RuntimeError, ValueError, zipfile.BadZipFile):
                continue
            candidates = _string_candidates(name, raw)
            if not candidates:
                continue
            scanned_files.append(name)
            if name.endswith(".so"):
                native_libraries.append(_native_library_summary(name, raw, candidates))
            for candidate in candidates:
                text = candidate.strip()
                if not text:
                    continue
                lowered = text.lower()
                for match in URL_RE.findall(text):
                    key = (name, match)
                    if key not in seen_urls:
                        seen_urls.add(key)
                        urls.append({"file": name, "url": match})
                for match in HOST_HINT_RE.findall(text):
                    host = match.strip().lower()
                    key = (name, host)
                    if key not in seen_hosts:
                        seen_hosts.add(key)
                        direct_hosts.append({"file": name, "host": host})
                if secret_match := SECRET_INDICATOR_RE.search(text):
                    preview = _redact_secret(secret_match.group(0))
                    key = (name, preview)
                    if key not in seen_secrets:
                        seen_secrets.add(key)
                        secrets.append({"file": name, "preview": preview})
                if pin_match := CERT_PIN_RE.search(text):
                    preview = _string_preview(pin_match.group(0))
                    key = (name, preview)
                    if key not in seen_pins:
                        seen_pins.add(key)
                        pins.append({"file": name, "preview": preview})
                _record_named_patterns(libraries, lowered, name, text)
                _record_named_patterns(trackers, lowered, name, text)
                _record_signal_patterns(signals, lowered, name, text)

    library_items = _finalize_named_matches(libraries)
    tracker_items = _finalize_named_matches(trackers)
    signal_items = _finalize_signal_matches(signals)
    jni_entry_point_count = sum(
        int(item.get("jni_entry_point_count") or 0) for item in native_libraries
    )
    return {
        "stats": {
            "scanned_file_count": len(scanned_files),
            "url_count": len(urls),
            "host_count": len(direct_hosts),
            "secret_indicator_count": len(secrets),
            "certificate_pin_indicator_count": len(pins),
            "library_count": len(library_items),
            "tracker_count": len(tracker_items),
            "code_signal_count": len(signal_items),
            "native_library_count": len(native_libraries),
            "jni_entry_point_count": jni_entry_point_count,
        },
        "scanned_files": scanned_files,
        "urls": urls[:25],
        "hosts": direct_hosts[:25],
        "hardcoded_secret_indicators": secrets[:25],
        "certificate_pin_indicators": pins[:25],
        "libraries": library_items,
        "trackers": tracker_items,
        "code_signals": signal_items,
        "native_libraries": native_libraries,
    }


def _candidate_names(names: list[str]) -> list[str]:
    def score(name: str) -> tuple[int, int, str]:
        path = pathlib.PurePosixPath(name)
        suffix = path.suffix.lower()
        priority = 5
        if name.startswith("assets/") or name.startswith("res/raw/"):
            priority = 0
        elif suffix in TEXT_FILE_SUFFIXES:
            priority = 1
        elif name.endswith(".dex") or name.endswith(".so"):
            priority = 2
        elif name.startswith("res/") or name.startswith("META-INF/"):
            priority = 3
        return (priority, len(name), name)

    return sorted(names, key=score)[:48]


def _string_candidates(name: str, raw: bytes) -> list[str]:
    suffix = pathlib.PurePosixPath(name).suffix.lower()
    if suffix in TEXT_FILE_SUFFIXES or name.endswith((".smali", ".kt", ".java")):
        try:
            return [
                line for line in raw.decode("utf-8", errors="ignore").splitlines() if line.strip()
            ]
        except Exception:
            return []
    return [match.decode("utf-8", errors="ignore") for match in ASCII_STRING_RE.findall(raw)]


def _match_registry(
    patterns: tuple[tuple[str, str, str, tuple[str, ...]], ...],
) -> dict[str, dict[str, Any]]:
    return {
        match_id: {
            "id": match_id,
            "label": label,
            "category": category,
            "tokens": tokens,
            "evidence": [],
        }
        for match_id, label, category, tokens in patterns
    }


def _signal_registry(
    patterns: tuple[tuple[str, str, str, str, tuple[str, ...]], ...],
) -> dict[str, dict[str, Any]]:
    return {
        signal_id: {
            "id": signal_id,
            "label": label,
            "severity": severity,
            "rationale": rationale,
            "tokens": tokens,
            "evidence": [],
        }
        for signal_id, label, severity, rationale, tokens in patterns
    }


def _record_named_patterns(
    registry: dict[str, dict[str, Any]], lowered: str, file_name: str, original: str
) -> None:
    for item in registry.values():
        if any(token in lowered for token in item["tokens"]):
            _append_evidence(item["evidence"], file_name, original)


def _record_signal_patterns(
    registry: dict[str, dict[str, Any]], lowered: str, file_name: str, original: str
) -> None:
    for item in registry.values():
        if any(token in lowered for token in item["tokens"]):
            _append_evidence(item["evidence"], file_name, original)


def _append_evidence(evidence: list[dict[str, str]], file_name: str, original: str) -> None:
    preview = _string_preview(original)
    entry = {"file": file_name, "preview": preview}
    if entry in evidence:
        return
    if len(evidence) < 3:
        evidence.append(entry)


def _finalize_named_matches(registry: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for item in registry.values():
        if not item["evidence"]:
            continue
        items.append(
            {
                "id": item["id"],
                "label": item["label"],
                "category": item["category"],
                "evidence": item["evidence"],
            }
        )
    return sorted(items, key=lambda item: item["label"])[:20]


def _finalize_signal_matches(registry: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for item in registry.values():
        if not item["evidence"]:
            continue
        items.append(
            {
                "id": item["id"],
                "label": item["label"],
                "severity": item["severity"],
                "rationale": item["rationale"],
                "evidence": item["evidence"],
            }
        )
    return sorted(items, key=lambda item: item["label"])[:20]


def _native_library_summary(name: str, raw: bytes, candidates: list[str]) -> dict[str, Any]:
    parts = pathlib.PurePosixPath(name).parts
    abi = parts[1] if len(parts) >= 3 and parts[0] == "lib" else None
    jni_matches = sorted(
        {
            candidate.strip()
            for candidate in candidates
            if candidate.startswith("Java_") or candidate == "JNI_OnLoad"
        }
    )
    return {
        "file": name,
        "abi": abi,
        "name": pathlib.PurePosixPath(name).name,
        "size_bytes": len(raw),
        "jni_entry_point_count": len(jni_matches),
        "jni_entry_points": jni_matches[:12],
    }
