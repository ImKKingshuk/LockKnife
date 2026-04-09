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
from lockknife.core.feature_matrix import iter_features
from lockknife.core.health import doctor_status, health_status
from lockknife.core.plugin_loader import plugin_inventory
from lockknife.core.serialize import write_csv, write_json
from lockknife.modules.reporting.chain_of_custody import (
    EvidenceItem,
    generate_chain_of_custody,
)
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
from lockknife.modules.security.owasp import mastg_summary
from lockknife.modules.security.selinux import get_selinux_status
from lockknife.modules.credentials.wifi import extract_wifi_passwords
from lockknife.modules.extraction._browser_extract_chrome import (
    extract_chrome_bookmarks,
    extract_chrome_cookies,
    extract_chrome_downloads,
    extract_chrome_history,
    extract_chrome_saved_logins,
)
from lockknife.modules.extraction._browser_extract_firefox import (
    extract_firefox_bookmarks,
    extract_firefox_history,
    extract_firefox_saved_logins,
)
from lockknife.modules.extraction.call_logs import extract_call_logs
from lockknife.modules.extraction.contacts import extract_contacts
from lockknife.modules.extraction.location import (
    extract_location_artifacts,
    extract_location_snapshot,
)
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
from lockknife.modules.forensics.correlation import correlate_artifacts_json_blobs
from lockknife.modules.forensics.recovery import recover_deleted_records
from lockknife.modules.forensics.snapshot import create_snapshot
from lockknife.modules.forensics.sqlite_analyzer import analyze_sqlite
from lockknife.modules.forensics.timeline import build_timeline, build_timeline_report
from lockknife.modules.intelligence.cve import (
    android_cve_risk_score,
    correlate_cves_for_apk_package,
    correlate_cves_for_kernel_version,
)
from lockknife.modules.intelligence.ioc import (
    detect_iocs,
    load_stix_indicators_from_url,
    load_taxii_indicators,
)
from lockknife.modules.intelligence.otx import indicator_reputation
from lockknife.modules.intelligence.virustotal import (
    domain_report,
    file_report,
    ip_report,
    submit_url_for_analysis,
    url_report,
)
from lockknife.modules.network.api_discovery import (
    extract_api_endpoints_from_pcap,
    summarize_pcap,
)
from lockknife.modules.network.capture import capture_pcap
from lockknife.modules._case_enrichment_orchestrator import run_case_enrichment
from lockknife.modules._case_enrichment_payloads import (
    anomaly_payload,
    api_discovery_payload,
    cve_payload,
    ioc_payload,
    network_summary_payload,
    otx_payload,
    password_payload,
    stix_payload,
    taxii_payload,
    virustotal_payload,
)
from lockknife.modules.ai.anomaly import anomaly_scores
from lockknife.modules.ai.password_predictor import PasswordPredictor
from lockknife.modules.crypto_wallet.wallet import (
    enrich_wallet_addresses,
    extract_wallet_addresses_from_sqlite,
    list_wallet_transactions,
)
from lockknife.modules.runtime._session_manager_live import (
    get_managed_runtime_session,
    list_managed_runtime_sessions,
    reconnect_managed_runtime_session,
    reload_managed_runtime_session,
    start_managed_runtime_session,
    stop_managed_runtime_session,
)
from lockknife.modules.runtime._session_manager_preflight import runtime_preflight
from lockknife.modules.runtime.frida_manager import FridaManager
from lockknife.modules.runtime.hooks import root_bypass_script, ssl_pinning_bypass_script
from lockknife.modules.runtime.memory import heap_dump, memory_search
from lockknife.modules.runtime.tracer import method_tracer_script
from lockknife.modules.apk.decompile import decompile_apk_report, extract_dex_headers, parse_apk_manifest
from lockknife.modules.apk.permissions import score_permissions
from lockknife.modules.apk.static_analysis import analyze_apk
from lockknife.modules.apk.vulnerability import vulnerability_report
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
    module.__dict__["plugin_inventory"] = plugin_inventory
    module.__dict__["iter_features"] = iter_features
    module.__dict__["doctor_status"] = doctor_status
    module.__dict__["health_status"] = health_status
    module.__dict__["write_csv"] = write_csv
    module.__dict__["write_json"] = write_json
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
    module.__dict__["generate_chain_of_custody"] = generate_chain_of_custody
    module.__dict__["build_report_context"] = build_report_context
    module.__dict__["export_csv"] = export_csv
    module.__dict__["write_html_report"] = write_html_report
    module.__dict__["export_json"] = export_json
    module.__dict__["write_pdf_report"] = write_pdf_report
    module.__dict__["assess_attack_surface"] = assess_attack_surface
    module.__dict__["analyze_bootloader"] = analyze_bootloader
    module.__dict__["run_device_audit"] = run_device_audit
    module.__dict__["analyze_hardware_security"] = analyze_hardware_security
    module.__dict__["scan_with_yara"] = scan_with_yara
    module.__dict__["scan_network"] = scan_network
    module.__dict__["get_selinux_status"] = get_selinux_status
    module.__dict__["mastg_summary"] = mastg_summary
    module.__dict__["extract_wifi_passwords"] = extract_wifi_passwords
    module.__dict__["extract_chrome_bookmarks"] = extract_chrome_bookmarks
    module.__dict__["extract_chrome_cookies"] = extract_chrome_cookies
    module.__dict__["extract_chrome_downloads"] = extract_chrome_downloads
    module.__dict__["extract_chrome_history"] = extract_chrome_history
    module.__dict__["extract_chrome_saved_logins"] = extract_chrome_saved_logins
    module.__dict__["extract_firefox_bookmarks"] = extract_firefox_bookmarks
    module.__dict__["extract_firefox_history"] = extract_firefox_history
    module.__dict__["extract_firefox_saved_logins"] = extract_firefox_saved_logins
    module.__dict__["extract_call_logs"] = extract_call_logs
    module.__dict__["extract_contacts"] = extract_contacts
    module.__dict__["extract_location_artifacts"] = extract_location_artifacts
    module.__dict__["extract_location_snapshot"] = extract_location_snapshot
    module.__dict__["extract_media_with_exif"] = extract_media_with_exif
    module.__dict__["extract_signal_artifacts"] = extract_signal_artifacts
    module.__dict__["extract_signal_messages"] = extract_signal_messages
    module.__dict__["extract_telegram_artifacts"] = extract_telegram_artifacts
    module.__dict__["extract_telegram_messages"] = extract_telegram_messages
    module.__dict__["extract_whatsapp_artifacts"] = extract_whatsapp_artifacts
    module.__dict__["extract_whatsapp_messages"] = extract_whatsapp_messages
    module.__dict__["extract_sms"] = extract_sms
    module.__dict__["correlate_artifacts_json_blobs"] = correlate_artifacts_json_blobs
    module.__dict__["recover_deleted_records"] = recover_deleted_records
    module.__dict__["create_snapshot"] = create_snapshot
    module.__dict__["analyze_sqlite"] = analyze_sqlite
    module.__dict__["build_timeline"] = build_timeline
    module.__dict__["build_timeline_report"] = build_timeline_report
    module.__dict__["android_cve_risk_score"] = android_cve_risk_score
    module.__dict__["correlate_cves_for_apk_package"] = correlate_cves_for_apk_package
    module.__dict__["correlate_cves_for_kernel_version"] = correlate_cves_for_kernel_version
    module.__dict__["detect_iocs"] = detect_iocs
    module.__dict__["load_stix_indicators_from_url"] = load_stix_indicators_from_url
    module.__dict__["load_taxii_indicators"] = load_taxii_indicators
    module.__dict__["indicator_reputation"] = indicator_reputation
    module.__dict__["domain_report"] = domain_report
    module.__dict__["file_report"] = file_report
    module.__dict__["ip_report"] = ip_report
    module.__dict__["submit_url_for_analysis"] = submit_url_for_analysis
    module.__dict__["url_report"] = url_report
    module.__dict__["extract_api_endpoints_from_pcap"] = extract_api_endpoints_from_pcap
    module.__dict__["summarize_pcap"] = summarize_pcap
    module.__dict__["capture_pcap"] = capture_pcap
    module.__dict__["anomaly_scores"] = anomaly_scores
    module.__dict__["PasswordPredictor"] = PasswordPredictor
    module.__dict__["anomaly_payload"] = anomaly_payload
    module.__dict__["api_discovery_payload"] = api_discovery_payload
    module.__dict__["cve_payload"] = cve_payload
    module.__dict__["ioc_payload"] = ioc_payload
    module.__dict__["network_summary_payload"] = network_summary_payload
    module.__dict__["otx_payload"] = otx_payload
    module.__dict__["password_payload"] = password_payload
    module.__dict__["run_case_enrichment"] = run_case_enrichment
    module.__dict__["stix_payload"] = stix_payload
    module.__dict__["taxii_payload"] = taxii_payload
    module.__dict__["virustotal_payload"] = virustotal_payload
    module.__dict__["extract_wallet_addresses_from_sqlite"] = extract_wallet_addresses_from_sqlite
    module.__dict__["enrich_wallet_addresses"] = enrich_wallet_addresses
    module.__dict__["list_wallet_transactions"] = list_wallet_transactions
    module.__dict__["FridaManager"] = FridaManager
    module.__dict__["root_bypass_script"] = root_bypass_script
    module.__dict__["ssl_pinning_bypass_script"] = ssl_pinning_bypass_script
    module.__dict__["heap_dump"] = heap_dump
    module.__dict__["memory_search"] = memory_search
    module.__dict__["get_managed_runtime_session"] = get_managed_runtime_session
    module.__dict__["list_managed_runtime_sessions"] = list_managed_runtime_sessions
    module.__dict__["reconnect_managed_runtime_session"] = reconnect_managed_runtime_session
    module.__dict__["reload_managed_runtime_session"] = reload_managed_runtime_session
    module.__dict__["runtime_preflight"] = runtime_preflight
    module.__dict__["start_managed_runtime_session"] = start_managed_runtime_session
    module.__dict__["stop_managed_runtime_session"] = stop_managed_runtime_session
    module.__dict__["method_tracer_script"] = method_tracer_script
    module.__dict__["decompile_apk_report"] = decompile_apk_report
    module.__dict__["extract_dex_headers"] = extract_dex_headers
    module.__dict__["parse_apk_manifest"] = parse_apk_manifest
    module.__dict__["score_permissions"] = score_permissions
    module.__dict__["analyze_apk"] = analyze_apk
    module.__dict__["vulnerability_report"] = vulnerability_report
    module.__dict__["export_pin_recovery"] = export_pin_recovery
    module.__dict__["export_gesture_recovery"] = export_gesture_recovery
    module.__dict__["export_wifi_credentials"] = export_wifi_credentials
    module.__dict__["inspect_keystore"] = inspect_keystore
    module.__dict__["list_keystore"] = list_keystore
    module.__dict__["pull_passkey_artifacts"] = pull_passkey_artifacts
    module.__dict__["recover_gesture"] = recover_gesture
    module.__dict__["recover_pin"] = recover_pin
    return callback
