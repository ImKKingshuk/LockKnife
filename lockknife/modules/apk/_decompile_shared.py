from __future__ import annotations



import re

from typing import Any



from lockknife.core.exceptions import LockKnifeError



ANDROID_NS = "http://schemas.android.com/apk/res/android"

ANDROID_ATTR = f"{{{ANDROID_NS}}}"

SUPPORTED_DECOMPILE_MODES = {"auto", "unpack", "apktool", "jadx", "hybrid"}

TEXT_FILE_SUFFIXES = {

    ".txt",

    ".json",

    ".xml",

    ".html",

    ".js",

    ".properties",

    ".cfg",

    ".conf",

    ".yml",

    ".yaml",

}

ASCII_STRING_RE = re.compile(rb"[ -~]{6,}")

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")

HOST_HINT_RE = re.compile(

    r"(?:^|[\s:=\"'])((?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|app|dev|ai|co|in|me|info|biz|edu|gov|xyz|cloud|local))(?:$|[\s/\"'])",

    re.IGNORECASE,

)

SECRET_INDICATOR_RE = re.compile(r"(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|authorization|bearer|password|passwd|secret)[^\n]{0,96}")

CERT_PIN_RE = re.compile(r"(?i)(pin[-_ ]?sha256|sha256/)[A-Za-z0-9+/=:_ -]{8,}")



class ApkError(LockKnifeError):
    pass



def _require_androguard() -> Any:
    try:
        from androguard.core.bytecodes.apk import APK
    except ImportError as e:
        raise ApkError("androguard is required (install extras: uv sync --extra apk)") from e
    return APK
