from __future__ import annotations

import dataclasses
import json
import pathlib
import time
from typing import Any, Callable, cast

from lockknife.core.case import (
    case_chain_of_custody_items,
    case_chain_of_custody_report,
    case_artifact_details,
    case_artifact_lineage,
    case_integrity_report,
    case_job_details,
    case_job_rerun_context,
    case_lineage_graph,
    case_output_path,
    complete_case_job,
    create_case_workspace,
    export_case_bundle,
    fail_case_job,
    find_case_artifact,
    generate_case_chain_of_custody,
    load_case_manifest,
    query_case_artifacts,
    query_case_jobs,
    query_case_runtime_sessions,
    register_case_artifact,
    register_case_artifact_with_status,
    start_case_job,
    summarize_case_manifest,
)
from lockknife.core.device import DeviceManager
from lockknife.core.feature_matrix import iter_features
from lockknife.core.health import doctor_status, health_status
from lockknife.core.serialize import write_csv, write_json
from lockknife.modules.credentials.fido2 import pull_passkey_artifacts
from lockknife.modules.credentials.gesture import export_gesture_recovery, recover_gesture
from lockknife.modules.credentials.keystore import inspect_keystore, list_keystore
from lockknife.modules.credentials.pin import export_pin_recovery, recover_pin
from lockknife.modules.credentials.wifi import export_wifi_credentials, extract_wifi_passwords
from lockknife.modules.extraction.browser import (
    extract_chrome_bookmarks,
    extract_chrome_cookies,
    extract_chrome_downloads,
    extract_chrome_history,
    extract_chrome_saved_logins,
    extract_firefox_bookmarks,
    extract_firefox_history,
    extract_firefox_saved_logins,
)
from lockknife.modules.extraction.call_logs import extract_call_logs
from lockknife.modules.extraction.contacts import extract_contacts
from lockknife.modules.extraction.location import extract_location_artifacts, extract_location_snapshot
from lockknife.modules.extraction.media import extract_media_with_exif
from lockknife.modules.extraction.messaging import (
    extract_signal_artifacts,
    extract_signal_messages,
    extract_telegram_artifacts,
    extract_telegram_messages,
    extract_whatsapp_artifacts,
    extract_whatsapp_messages,
)
from lockknife.modules.extraction.sms import extract_sms
from lockknife.modules.forensics.artifacts import parse_directory_as_aleapp, parse_forensics_directory
from lockknife.modules.forensics.aleapp_compat import looks_like_aleapp_output
from lockknife.modules.forensics.carving import carve_deleted_files
from lockknife.modules.forensics.correlation import correlate_artifacts_json_blobs
from lockknife.modules.forensics.parsers import decode_protobuf_file
from lockknife.modules.forensics.recovery import recover_deleted_records
from lockknife.modules.forensics.snapshot import create_snapshot
from lockknife.modules.forensics.sqlite_analyzer import analyze_sqlite
from lockknife.modules.forensics.timeline import build_timeline, build_timeline_report
from lockknife.modules.intelligence.cve import android_cve_risk_score, correlate_cves_for_apk_package, correlate_cves_for_kernel_version
from lockknife.modules.intelligence.ioc import detect_iocs, load_stix_indicators_from_url, load_taxii_indicators
from lockknife.modules.intelligence.otx import indicator_reputation
from lockknife.modules.intelligence.virustotal import domain_report, file_report, ip_report, submit_url_for_analysis, url_report
from lockknife.modules.network.api_discovery import extract_api_endpoints_from_pcap, summarize_pcap
from lockknife.modules.network.capture import capture_pcap
from lockknife.modules.reporting.chain_of_custody import EvidenceItem, build_chain_of_custody_payload, generate_chain_of_custody, sign_report_file
from lockknife.modules.reporting.context import build_report_context
from lockknife.modules.reporting.csv_export import export_csv
from lockknife.modules.reporting.html_report import write_html_report
from lockknife.modules.reporting.json_export import export_json
from lockknife.modules.reporting.pdf_report import write_pdf_report
from lockknife.modules.security.attack_surface import assess_attack_surface
from lockknife.modules.security.bootloader import analyze_bootloader
from lockknife.modules.security.device_audit import run_device_audit
from lockknife.modules.security.hardware import analyze_hardware_security
from lockknife.modules.security.malware import scan_with_yara
from lockknife.modules.security.network_scan import scan_network
from lockknife.modules.security.selinux import get_selinux_status
from lockknife.modules.security.owasp import mastg_summary
from lockknife.modules.ai.anomaly import anomaly_scores
from lockknife.modules.ai.password_predictor import PasswordPredictor, load_personal_data
from lockknife.modules.case_enrichment import (
    anomaly_payload,
    api_discovery_payload,
    cve_payload,
    ioc_payload,
    network_summary_payload,
    otx_payload,
    password_payload,
    run_case_enrichment,
    stix_payload,
    taxii_payload,
    virustotal_payload,
)
from lockknife.modules.crypto_wallet.wallet import (
    extract_wallet_addresses_from_sqlite,
    enrich_wallet_addresses,
    list_wallet_transactions,
)
from lockknife.modules.runtime.frida_manager import FridaManager
from lockknife.modules.runtime.hooks import (
    get_builtin_runtime_script,
    list_builtin_runtime_scripts,
    root_bypass_script,
    ssl_pinning_bypass_script,
    suggest_builtin_runtime_scripts,
)
from lockknife.modules.runtime.memory import heap_dump, memory_search
from lockknife.modules.runtime.session_manager import (
    get_managed_runtime_session,
    list_managed_runtime_sessions,
    reconnect_managed_runtime_session,
    reload_managed_runtime_session,
    runtime_preflight,
    start_managed_runtime_session,
    stop_managed_runtime_session,
)
from lockknife.modules.runtime.tracer import method_tracer_script
from lockknife.modules.apk.decompile import decompile_apk_report, extract_dex_headers, parse_apk_manifest
from lockknife.modules.apk.permissions import score_permissions
from lockknife.modules.apk._risk_summary import build_apk_risk_summary
from lockknife.modules.apk.static_analysis import analyze_apk, findings_from_manifest
from lockknife.modules.apk.vulnerability import vulnerability_report

from lockknife.core.plugin_loader import plugin_inventory

import sys

try:
    import lockknife.lockknife_core as lockknife_core  # noqa: F401 — Rust extension
except ImportError:
    lockknife_core = None  # type: ignore[assignment]



from lockknife_headless_cli._tui_callback_helpers import (
    _CaseJobTracker,
    _JOB_TRACKER_STACK,
    _JOB_MANAGED_ACTION_PREFIXES,
    _asdict,
    _current_job_tracker,
    _job_action_label,
    _should_track_case_job,
    _job_device_serial,
    _maybe_start_case_job,
    _payload_has_partial_signal,
    _job_recovery_hint,
    _job_json_payload,
    _ok,
    _err,
    _require,
    _opt,
    _path_param,
    _csv_list,
    _int_param,
    _bool_param,
    _json_dict_param,
    _resolve_case_output,
    _register_case_output,
    _safe_name,
    _require_runtime_case_dir,
    _runtime_session_name,
    _case_filter_kwargs,
    _case_job_filter_kwargs,
    _artifact_ref_from_params,
    _template_path,
    _resolve_report_case_id,
    _resolve_report_examiner,
    _report_rows,
    _custody_evidence_items,
    _render_integrity_text,
    _json_from_param,
    _load_config_text,
)

from lockknife_headless_cli._tui_callback_core import handle as _handle_core
from lockknife_headless_cli._tui_callback_credentials import handle as _handle_credentials
from lockknife_headless_cli._tui_callback_extraction import handle as _handle_extraction
from lockknife_headless_cli._tui_callback_forensics import handle as _handle_forensics
from lockknife_headless_cli._tui_callback_report import handle as _handle_report
from lockknife_headless_cli._tui_callback_case import handle as _handle_case
from lockknife_headless_cli._tui_callback_network import handle as _handle_network
from lockknife_headless_cli._tui_callback_apk import handle as _handle_apk
from lockknife_headless_cli._tui_callback_runtime import handle as _handle_runtime
from lockknife_headless_cli._tui_callback_security import handle as _handle_security
from lockknife_headless_cli._tui_callback_intelligence import handle as _handle_intelligence
from lockknife_headless_cli._tui_callback_ai import handle as _handle_ai
from lockknife_headless_cli._tui_callback_crypto import handle as _handle_crypto
from lockknife_headless_cli._tui_callback_misc import handle as _handle_misc
from lockknife_headless_cli._tui_callback_analyze import handle as _handle_analyze
from lockknife_headless_cli._tui_callback_plugins import handle as _handle_plugins
from lockknife_headless_cli._tui_callback_exploit import handle as _handle_exploit


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
            if _job_tracker is not None and _JOB_TRACKER_STACK and _JOB_TRACKER_STACK[-1] is _job_tracker:
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

    setattr(module, "_dispatch_callback", callback)
    return callback
