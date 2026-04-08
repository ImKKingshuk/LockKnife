from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast


def handle(app: Any, action: str, params: dict[str, Any], *, cb: Any) -> dict[str, Any] | None:
    callback = cb._dispatch_callback
    callback = cast(Callable[[str, dict[str, Any]], dict[str, Any]], callback)
    dataclasses = cb.dataclasses
    json = cb.json
    pathlib = cb.pathlib
    time = cb.time
    _asdict = cb._asdict
    _ok = cast(Callable[[Any, str], dict[str, Any]], cb._ok)
    _err = cast(Callable[[str], dict[str, Any]], cb._err)
    _require = cb._require
    _opt = cb._opt
    _path_param = cb._path_param
    _csv_list = cb._csv_list
    _int_param = cb._int_param
    _bool_param = cb._bool_param
    _json_dict_param = cb._json_dict_param
    _resolve_case_output = cb._resolve_case_output
    _register_case_output = cb._register_case_output
    _safe_name = cb._safe_name
    _require_runtime_case_dir = cb._require_runtime_case_dir
    _runtime_session_name = cb._runtime_session_name
    _case_filter_kwargs = cb._case_filter_kwargs
    _case_job_filter_kwargs = cb._case_job_filter_kwargs
    _artifact_ref_from_params = cb._artifact_ref_from_params
    _template_path = cb._template_path
    _resolve_report_case_id = cb._resolve_report_case_id
    _resolve_report_examiner = cb._resolve_report_examiner
    _report_rows = cb._report_rows
    _custody_evidence_items = cb._custody_evidence_items
    _render_integrity_text = cb._render_integrity_text
    _json_from_param = cb._json_from_param
    _load_config_text = cb._load_config_text
    case_chain_of_custody_items = cb.case_chain_of_custody_items
    case_artifact_details = cb.case_artifact_details
    case_artifact_lineage = cb.case_artifact_lineage
    case_integrity_report = cb.case_integrity_report
    case_job_details = cb.case_job_details
    case_job_rerun_context = cb.case_job_rerun_context
    case_lineage_graph = cb.case_lineage_graph
    case_output_path = cb.case_output_path
    create_case_workspace = cb.create_case_workspace
    export_case_bundle = cb.export_case_bundle
    find_case_artifact = cb.find_case_artifact
    generate_case_chain_of_custody = cb.generate_case_chain_of_custody
    load_case_manifest = cb.load_case_manifest
    query_case_artifacts = cb.query_case_artifacts
    query_case_jobs = cb.query_case_jobs
    query_case_runtime_sessions = cb.query_case_runtime_sessions
    register_case_artifact = cb.register_case_artifact
    register_case_artifact_with_status = cb.register_case_artifact_with_status
    summarize_case_manifest = cb.summarize_case_manifest
    iter_features = cb.iter_features
    doctor_status = cb.doctor_status
    health_status = cb.health_status
    write_csv = cb.write_csv
    write_json = cb.write_json
    recover_gesture = cb.recover_gesture
    list_keystore = cb.list_keystore
    recover_pin = cb.recover_pin
    extract_wifi_passwords = cb.extract_wifi_passwords
    extract_chrome_bookmarks = cb.extract_chrome_bookmarks
    extract_chrome_cookies = cb.extract_chrome_cookies
    extract_chrome_downloads = cb.extract_chrome_downloads
    extract_chrome_history = cb.extract_chrome_history
    extract_chrome_saved_logins = cb.extract_chrome_saved_logins
    extract_firefox_bookmarks = cb.extract_firefox_bookmarks
    extract_firefox_history = cb.extract_firefox_history
    extract_firefox_saved_logins = cb.extract_firefox_saved_logins
    extract_call_logs = cb.extract_call_logs
    extract_contacts = cb.extract_contacts
    extract_location_artifacts = cb.extract_location_artifacts
    extract_location_snapshot = cb.extract_location_snapshot
    extract_media_with_exif = cb.extract_media_with_exif
    extract_signal_artifacts = cb.extract_signal_artifacts
    extract_signal_messages = cb.extract_signal_messages
    extract_telegram_artifacts = cb.extract_telegram_artifacts
    extract_telegram_messages = cb.extract_telegram_messages
    extract_whatsapp_artifacts = cb.extract_whatsapp_artifacts
    extract_whatsapp_messages = cb.extract_whatsapp_messages
    extract_sms = cb.extract_sms
    correlate_artifacts_json_blobs = cb.correlate_artifacts_json_blobs
    recover_deleted_records = cb.recover_deleted_records
    create_snapshot = cb.create_snapshot
    analyze_sqlite = cb.analyze_sqlite
    build_timeline = cb.build_timeline
    correlate_cves_for_apk_package = cb.correlate_cves_for_apk_package
    detect_iocs = cb.detect_iocs
    load_stix_indicators_from_url = cb.load_stix_indicators_from_url
    load_taxii_indicators = cb.load_taxii_indicators
    indicator_reputation = cb.indicator_reputation
    file_report = cb.file_report
    extract_api_endpoints_from_pcap = cb.extract_api_endpoints_from_pcap
    summarize_pcap = cb.summarize_pcap
    capture_pcap = cb.capture_pcap
    EvidenceItem = cb.EvidenceItem
    generate_chain_of_custody = cb.generate_chain_of_custody
    build_report_context = cb.build_report_context
    export_csv = cb.export_csv
    write_html_report = cb.write_html_report
    export_json = cb.export_json
    write_pdf_report = cb.write_pdf_report
    assess_attack_surface = cb.assess_attack_surface
    analyze_bootloader = cb.analyze_bootloader
    run_device_audit = cb.run_device_audit
    analyze_hardware_security = cb.analyze_hardware_security
    scan_with_yara = cb.scan_with_yara
    scan_network = cb.scan_network
    get_selinux_status = cb.get_selinux_status
    mastg_summary = cb.mastg_summary
    anomaly_scores = cb.anomaly_scores
    PasswordPredictor = cb.PasswordPredictor
    anomaly_payload = cb.anomaly_payload
    api_discovery_payload = cb.api_discovery_payload
    cve_payload = cb.cve_payload
    ioc_payload = cb.ioc_payload
    network_summary_payload = cb.network_summary_payload
    otx_payload = cb.otx_payload
    password_payload = cb.password_payload
    run_case_enrichment = cb.run_case_enrichment
    stix_payload = cb.stix_payload
    taxii_payload = cb.taxii_payload
    virustotal_payload = cb.virustotal_payload
    extract_wallet_addresses_from_sqlite = cb.extract_wallet_addresses_from_sqlite
    enrich_wallet_addresses = cb.enrich_wallet_addresses
    list_wallet_transactions = cb.list_wallet_transactions
    FridaManager = cb.FridaManager
    root_bypass_script = cb.root_bypass_script
    ssl_pinning_bypass_script = cb.ssl_pinning_bypass_script
    heap_dump = cb.heap_dump
    memory_search = cb.memory_search
    get_managed_runtime_session = cb.get_managed_runtime_session
    list_managed_runtime_sessions = cb.list_managed_runtime_sessions
    reconnect_managed_runtime_session = cb.reconnect_managed_runtime_session
    reload_managed_runtime_session = cb.reload_managed_runtime_session
    runtime_preflight = cb.runtime_preflight
    start_managed_runtime_session = cb.start_managed_runtime_session
    stop_managed_runtime_session = cb.stop_managed_runtime_session
    method_tracer_script = cb.method_tracer_script
    decompile_apk_report = cb.decompile_apk_report
    extract_dex_headers = cb.extract_dex_headers
    parse_apk_manifest = cb.parse_apk_manifest
    score_permissions = cb.score_permissions
    analyze_apk = cb.analyze_apk
    vulnerability_report = cb.vulnerability_report

    if action == "case.init":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        target_serials = _csv_list(params.get("target_serials"))
        selected_serial = _opt(getattr(app, "selected_device_serial", None))
        if not target_serials and selected_serial:
            target_serials = [selected_serial]
        create_case_workspace(
            case_dir=case_dir,
            case_id=_require(params, "case_id"),
            examiner=_require(params, "examiner"),
            title=_require(params, "title"),
            notes=_opt(params.get("notes")),
            target_serials=target_serials,
        )
        payload = summarize_case_manifest(case_dir)
        payload["case_dir"] = str(case_dir)
        return _ok(payload, f"Case workspace ready at {case_dir}")

    if action == "case.summary":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        payload = summarize_case_manifest(case_dir, **_case_filter_kwargs(params))
        return _ok(payload, f"Case summary ready for {case_dir}")

    if action == "case.jobs":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        payload = query_case_jobs(
            case_dir,
            **_case_job_filter_kwargs(params),
            query=_opt(params.get("query")),
            limit=_int_param(params.get("limit")),
        )
        return _ok(payload, f"Job history ready for {case_dir}")

    if action == "case.job":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        payload = case_job_details(case_dir, job_id=_require(params, "job_id"))
        if payload is None:
            raise ValueError("Job not found")
        return _ok(payload, f"Job detail ready for {payload['job']['job_id']}")

    if action == "case.graph":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        payload = case_lineage_graph(case_dir, **_case_filter_kwargs(params))
        return _ok(payload, f"Case lineage graph ready for {case_dir}")

    if action == "case.artifacts":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        payload = query_case_artifacts(
            case_dir,
            **_case_filter_kwargs(params),
            query=_opt(params.get("query")),
            path_contains=_opt(params.get("path_contains")),
            metadata_contains=_opt(params.get("metadata_contains")),
            limit=_int_param(params.get("limit")),
        )
        return _ok(payload, f"Artifact search ready for {case_dir}")

    if action == "case.artifact":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        payload = case_artifact_details(case_dir, **_artifact_ref_from_params(params))
        if payload is None:
            raise ValueError("Artifact not found")
        return _ok(payload, f"Artifact detail ready for {payload['artifact']['artifact_id']}")

    if action == "case.lineage":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        payload = case_artifact_lineage(case_dir, **_artifact_ref_from_params(params))
        if payload is None:
            raise ValueError("Artifact not found")
        return _ok(payload, f"Artifact lineage ready for {payload['artifact']['artifact_id']}")

    if action == "case.export":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        output = pathlib.Path(
            str(
                params.get("output")
                or case_output_path(
                    case_dir, area="exports", filename=f"{case_dir.name}_bundle.zip"
                )
            )
        )
        payload = export_case_bundle(
            case_dir=case_dir,
            output_path=output,
            include_registered_artifacts=_bool_param(params.get("include_registered_artifacts")),
            **_case_filter_kwargs(params),
        )
        return _ok(payload, f"Export bundle saved to {output}")

    if action == "case.enrich":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        payload = run_case_enrichment(
            case_dir=case_dir,
            artifact_id=_opt(params.get("artifact_id")),
            categories=_csv_list(params.get("categories")),
            exclude_categories=_csv_list(params.get("exclude_categories")),
            source_commands=_csv_list(params.get("source_commands")),
            device_serials=_csv_list(params.get("device_serials")),
            limit=_int_param(params.get("limit")),
            reputation_limit=int(params.get("reputation_limit") or 10),
            output=_path_param(params.get("output")),
        )
        return _ok(payload, f"Case enrichment bundle saved to {payload['output']}")

    if action == "case.register":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        device_serial = _opt(params.get("device_serial")) or _opt(
            getattr(app, "selected_device_serial", None)
        )
        metadata = _json_dict_param(params.get("metadata_json"))
        result = register_case_artifact_with_status(
            case_dir=case_dir,
            path=pathlib.Path(_require(params, "path")),
            category=_require(params, "category"),
            source_command=_require(params, "source_command"),
            device_serial=device_serial,
            input_paths=_csv_list(params.get("input_paths")),
            parent_artifact_ids=_csv_list(params.get("parent_artifact_ids")),
            metadata=metadata,
            on_conflict=str(params.get("on_conflict") or "auto").lower(),
        )
        payload = dataclasses.asdict(result.artifact)
        payload["registration_action"] = result.action
        return _ok(payload, f"Artifact {result.action}: {result.artifact.artifact_id}")

    if action == "case.resume_job":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        payload = case_job_rerun_context(case_dir, job_id=_require(params, "job_id"), mode="resume")
        if payload is None:
            raise ValueError("Job not found")
        execution_params = dict(payload["params"])
        execution_params["case_dir"] = str(case_dir)
        execution_params["resume_job_id"] = payload["job"]["job_id"]
        return callback(str(payload["action_id"]), execution_params)

    if action == "case.retry_job":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        payload = case_job_rerun_context(case_dir, job_id=_require(params, "job_id"), mode="retry")
        if payload is None:
            raise ValueError("Job not found")
        execution_params = dict(payload["params"])
        execution_params["case_dir"] = str(case_dir)
        execution_params["retry_job_id"] = payload["job"]["job_id"]
        return callback(str(payload["action_id"]), execution_params)

    if action == "case.runtime_sessions":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        session_id = _opt(params.get("session_id"))
        limit = _int_param(params.get("limit"))
        # Using query_case_runtime_sessions
        payload = {
            "sessions": query_case_runtime_sessions(case_dir, session_id=session_id)
            if session_id
            else query_case_runtime_sessions(case_dir)[:limit]
        }
        return _ok(payload, f"Runtime sessions ready for {case_dir}")

    if action == "case.chain_of_custody":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        out_format = str(params.get("format") or "json").lower()
        suffix = "txt" if out_format in ["txt", "md"] else "json"
        output = _path_param(params.get("output"))
        if not output:
            output, _derived = _resolve_case_output(
                None,
                case_dir,
                area="reports",
                filename=f"chain_of_custody_report.{suffix}",
            )

        payload = generate_case_chain_of_custody(case_dir)
        if output is not None:
            if suffix == "json":
                write_json(output, payload)
            else:
                # Basic text formatting fallback
                output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return _ok(payload, f"Chain of custody saved to {output}")
        return _ok(payload, "Chain of custody generated")

    if action == "case.integrity":
        case_dir = pathlib.Path(_require(params, "case_dir"))
        out_format = str(params.get("format") or "json").lower()
        suffix = "txt" if out_format in ["txt", "md"] else "json"
        output = _path_param(params.get("output"))
        if not output:
            output, _derived = _resolve_case_output(
                None,
                case_dir,
                area="reports",
                filename=f"integrity_report.{suffix}",
            )

        report_payload = case_integrity_report(case_dir)
        if output is not None:
            if suffix == "json":
                write_json(output, report_payload)
            else:
                output.write_text(_render_integrity_text(report_payload), encoding="utf-8")
            return _ok(report_payload, f"Integrity report saved to {output}")
        return _ok(report_payload, "Integrity report generated")

    return None
