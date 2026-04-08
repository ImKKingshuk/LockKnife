from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any

try:
    import lockknife.lockknife_core as _lockknife_core  # noqa: F401 — Rust extension
except ImportError:
    lockknife_core: Any | None = None
else:
    lockknife_core = _lockknife_core


from lockknife_headless_cli._tui_callback_ai import handle as _handle_ai
from lockknife_headless_cli._tui_callback_analyze import handle as _handle_analyze
from lockknife_headless_cli._tui_callback_apk import handle as _handle_apk
from lockknife_headless_cli._tui_callback_case import handle as _handle_case
from lockknife_headless_cli._tui_callback_core import handle as _handle_core
from lockknife_headless_cli._tui_callback_credentials import handle as _handle_credentials
from lockknife_headless_cli._tui_callback_crypto import handle as _handle_crypto
from lockknife_headless_cli._tui_callback_exploit import handle as _handle_exploit
from lockknife_headless_cli._tui_callback_extraction import handle as _handle_extraction
from lockknife_headless_cli._tui_callback_forensics import handle as _handle_forensics
from lockknife_headless_cli._tui_callback_helpers import (
    _JOB_TRACKER_STACK,
    _err,
    _maybe_start_case_job,
)
from lockknife_headless_cli._tui_callback_intelligence import handle as _handle_intelligence
from lockknife_headless_cli._tui_callback_misc import handle as _handle_misc
from lockknife_headless_cli._tui_callback_network import handle as _handle_network
from lockknife_headless_cli._tui_callback_plugins import handle as _handle_plugins
from lockknife_headless_cli._tui_callback_report import handle as _handle_report
from lockknife_headless_cli._tui_callback_runtime import handle as _handle_runtime
from lockknife_headless_cli._tui_callback_security import handle as _handle_security

_HANDLERS = (
    _handle_credentials,
    _handle_core,
    _handle_extraction,
    _handle_forensics,
    _handle_report,
    _handle_case,
    _handle_network,
    _handle_apk,
    _handle_runtime,
    _handle_security,
    _handle_intelligence,
    _handle_ai,
    _handle_crypto,
    _handle_analyze,
    _handle_plugins,
    _handle_misc,
    _handle_exploit,
)


def build_tui_callback(app: Any) -> Callable[[str, dict[str, Any]], dict[str, Any]]:
    module = sys.modules[__name__]

    def callback(action: str, params: dict[str, Any]) -> dict[str, Any]:
        import time as _time

        _t0 = _time.perf_counter()
        _err_flag = False
        _job_tracker = _maybe_start_case_job(action, params)
        if _job_tracker is not None:
            _JOB_TRACKER_STACK.append(_job_tracker)
        try:
            for handler in _HANDLERS:
                result = handler(app, action, params, cb=module)
                if result is not None:
                    return result
            return _err(f"Unsupported action: {action}")
        except Exception as exc:
            _err_flag = True
            return _err(str(exc))
        finally:
            if (
                _job_tracker is not None
                and _JOB_TRACKER_STACK
                and _JOB_TRACKER_STACK[-1] is _job_tracker
            ):
                _JOB_TRACKER_STACK.pop()
            try:
                from lockknife.core.metrics import _entry

                _elapsed = (_time.perf_counter() - _t0) * 1000.0
                _e = _entry(f"tui.{action}")
                _e["count"] += 1.0
                if _err_flag:
                    _e["error_count"] += 1.0
                _e["total_ms"] += _elapsed
                if _elapsed > _e["max_ms"]:
                    _e["max_ms"] = _elapsed
            except (ImportError, KeyError, TypeError, ValueError):
                pass

    module.__dict__["_dispatch_callback"] = callback
    return callback
