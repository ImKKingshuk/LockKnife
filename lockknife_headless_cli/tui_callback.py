from __future__ import annotations

import dataclasses
import json
import pathlib
import sys
import time
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
from lockknife.core.case import (
    case_artifact_details,
    case_artifact_lineage,
    case_chain_of_custody_items,
    case_integrity_report,
    case_job_details,
    case_job_rerun_context,
    case_lineage_graph,
    case_output_path,
    create_case_workspace,
    export_case_bundle,
    find_case_artifact,
    load_case_manifest,
    query_case_artifacts,
    query_case_jobs,
    query_case_runtime_sessions,
    register_case_artifact,
    register_case_artifact_with_status,
    summarize_case_manifest,
)
from lockknife.modules.reporting.chain_of_custody import EvidenceItem
from lockknife_headless_cli._credential_workflows import (
    export_gesture_recovery,
    export_pin_recovery,
    export_wifi_credentials,
    inspect_keystore,
    list_keystore,
    pull_passkey_artifacts,
    recover_gesture,
    recover_pin,
)
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
    _asdict,
    _artifact_ref_from_params,
    _bool_param,
    _case_filter_kwargs,
    _case_job_filter_kwargs,
    _csv_list,
    _custody_evidence_items,
    _err,
    _int_param,
    _json_dict_param,
    _json_from_param,
    _load_config_text,
    _maybe_start_case_job,
    _ok,
    _opt,
    _path_param,
    _register_case_output,
    _render_integrity_text,
    _require,
    _require_runtime_case_dir,
    _resolve_case_output,
    _resolve_report_case_id,
    _resolve_report_examiner,
    _report_rows,
    _runtime_session_name,
    _safe_name,
    _template_path,
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
    module.__dict__["_ok"] = _ok
    module.__dict__["_err"] = _err
    module.__dict__["_opt"] = _opt
    module.__dict__["_bool_param"] = _bool_param
    module.__dict__["_int_param"] = _int_param
    module.__dict__["_path_param"] = _path_param
    module.__dict__["_csv_list"] = _csv_list
    module.__dict__["_json_dict_param"] = _json_dict_param
    module.__dict__["_require"] = _require
    module.__dict__["_asdict"] = _asdict
    module.__dict__["_artifact_ref_from_params"] = _artifact_ref_from_params
    module.__dict__["_case_filter_kwargs"] = _case_filter_kwargs
    module.__dict__["_case_job_filter_kwargs"] = _case_job_filter_kwargs
    module.__dict__["_custody_evidence_items"] = _custody_evidence_items
    module.__dict__["_json_from_param"] = _json_from_param
    module.__dict__["_load_config_text"] = _load_config_text
    module.__dict__["_register_case_output"] = _register_case_output
    module.__dict__["_render_integrity_text"] = _render_integrity_text
    module.__dict__["_require_runtime_case_dir"] = _require_runtime_case_dir
    module.__dict__["_resolve_case_output"] = _resolve_case_output
    module.__dict__["_resolve_report_case_id"] = _resolve_report_case_id
    module.__dict__["_resolve_report_examiner"] = _resolve_report_examiner
    module.__dict__["_report_rows"] = _report_rows
    module.__dict__["_runtime_session_name"] = _runtime_session_name
    module.__dict__["_safe_name"] = _safe_name
    module.__dict__["_template_path"] = _template_path
    module.__dict__["dataclasses"] = dataclasses
    module.__dict__["json"] = json
    module.__dict__["pathlib"] = pathlib
    module.__dict__["time"] = time
    module.__dict__["lockknife_core"] = lockknife_core
    module.__dict__["case_chain_of_custody_items"] = case_chain_of_custody_items
    module.__dict__["case_artifact_details"] = case_artifact_details
    module.__dict__["case_artifact_lineage"] = case_artifact_lineage
    module.__dict__["case_integrity_report"] = case_integrity_report
    module.__dict__["case_job_details"] = case_job_details
    module.__dict__["case_job_rerun_context"] = case_job_rerun_context
    module.__dict__["case_lineage_graph"] = case_lineage_graph
    module.__dict__["case_output_path"] = case_output_path
    module.__dict__["create_case_workspace"] = create_case_workspace
    module.__dict__["export_case_bundle"] = export_case_bundle
    module.__dict__["find_case_artifact"] = find_case_artifact
    module.__dict__["load_case_manifest"] = load_case_manifest
    module.__dict__["query_case_artifacts"] = query_case_artifacts
    module.__dict__["query_case_jobs"] = query_case_jobs
    module.__dict__["query_case_runtime_sessions"] = query_case_runtime_sessions
    module.__dict__["register_case_artifact"] = register_case_artifact
    module.__dict__["register_case_artifact_with_status"] = register_case_artifact_with_status
    module.__dict__["summarize_case_manifest"] = summarize_case_manifest
    module.__dict__["EvidenceItem"] = EvidenceItem
    module.__dict__["export_pin_recovery"] = export_pin_recovery
    module.__dict__["export_gesture_recovery"] = export_gesture_recovery
    module.__dict__["export_wifi_credentials"] = export_wifi_credentials
    module.__dict__["inspect_keystore"] = inspect_keystore
    module.__dict__["list_keystore"] = list_keystore
    module.__dict__["pull_passkey_artifacts"] = pull_passkey_artifacts
    module.__dict__["recover_gesture"] = recover_gesture
    module.__dict__["recover_pin"] = recover_pin
    return callback
