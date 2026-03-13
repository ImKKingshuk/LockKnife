from __future__ import annotations

from typing import Any, Callable, cast


def handle(app: Any, action: str, params: dict[str, Any], *, cb: Any) -> dict[str, Any] | None:
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
    get_builtin_runtime_script = cb.get_builtin_runtime_script
    list_builtin_runtime_scripts = cb.list_builtin_runtime_scripts
    suggest_builtin_runtime_scripts = cb.suggest_builtin_runtime_scripts
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

    if action == "runtime.hook":
        app_id = _require(params, "app_id")
        script_path = pathlib.Path(_require(params, "script"))
        device_id = _opt(params.get("device_id"))
        timeout = float(params.get("timeout") or 1.0)
        case_dir = _require_runtime_case_dir(params)
        attach_mode = str(params.get("attach_mode") or "spawn")
        session_name = _runtime_session_name(params, default=f"hook-{_safe_name(app_id)}")
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"runtime_hook_{_safe_name(app_id)}_session.json",
        )
        payload = start_managed_runtime_session(
            case_dir=case_dir,
            name=session_name,
            app_id=app_id,
            session_kind="hook",
            source_command="runtime hook",
            script_source=script_path.read_text(encoding="utf-8"),
            script_label=script_path.name,
            device_id=device_id,
            attach_mode=attach_mode,
            input_paths=[str(script_path)],
            metadata={"source_script_path": str(script_path)},
            initial_wait_s=timeout,
            manager_factory=FridaManager,
        )
        if output is not None:
            write_json(output, payload)
            return _ok(payload, f"Managed runtime session saved to {output}")
        return _ok(payload, f"Managed hook session {payload['session']['session_id']} is active")

    if action == "runtime.load_builtin_script":
        app_id = _require(params, "app_id")
        builtin_script = _require(params, "builtin_script")
        device_id = _opt(params.get("device_id"))
        timeout = float(params.get("timeout") or 1.0)
        case_dir = _require_runtime_case_dir(params)
        attach_mode = str(params.get("attach_mode") or "spawn")
        descriptor = get_builtin_runtime_script(builtin_script)
        session_name = _runtime_session_name(params, default=f"builtin-{_safe_name(app_id)}-{descriptor['name']}")
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"runtime_builtin_{_safe_name(app_id)}_{_safe_name(str(descriptor['name']))}_session.json",
        )
        payload = start_managed_runtime_session(
            case_dir=case_dir,
            name=session_name,
            app_id=app_id,
            session_kind=str(descriptor["name"]),
            source_command="runtime load-builtin-script",
            builtin_script=str(descriptor["name"]),
            script_label=str(descriptor["file_name"]),
            device_id=device_id,
            attach_mode=attach_mode,
            metadata={"builtin_script": descriptor["name"], "builtin_category": descriptor["category"]},
            initial_wait_s=timeout,
            manager_factory=FridaManager,
        )
        payload["available_builtin_scripts"] = list_builtin_runtime_scripts()
        payload["suggested_builtin_scripts"] = suggest_builtin_runtime_scripts(app_id, session_kind=str(descriptor["name"]))
        if output is not None:
            write_json(output, payload)
            return _ok(payload, f"Managed built-in runtime session saved to {output}")
        return _ok(payload, f"Managed built-in runtime session {payload['session']['session_id']} is active")

    if action == "runtime.bypass_ssl":
        app_id = _require(params, "app_id")
        device_id = _opt(params.get("device_id"))
        timeout = float(params.get("timeout") or 1.0)
        case_dir = _require_runtime_case_dir(params)
        attach_mode = str(params.get("attach_mode") or "spawn")
        session_name = _runtime_session_name(params, default=f"ssl-{_safe_name(app_id)}")
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"runtime_bypass_ssl_{_safe_name(app_id)}_session.json",
        )
        payload = start_managed_runtime_session(
            case_dir=case_dir,
            name=session_name,
            app_id=app_id,
            session_kind="bypass_ssl",
            source_command="runtime bypass-ssl",
            builtin_script="ssl_bypass",
            script_label="ssl_bypass.js",
            device_id=device_id,
            attach_mode=attach_mode,
            metadata={"builtin_script": "ssl_bypass", "builtin_category": "network"},
            initial_wait_s=timeout,
            manager_factory=FridaManager,
        )
        if output is not None:
            write_json(output, payload)
            return _ok(payload, f"Managed SSL bypass session saved to {output}")
        return _ok(payload, f"Managed SSL bypass session {payload['session']['session_id']} is active")

    if action == "runtime.bypass_root":
        app_id = _require(params, "app_id")
        device_id = _opt(params.get("device_id"))
        timeout = float(params.get("timeout") or 1.0)
        case_dir = _require_runtime_case_dir(params)
        attach_mode = str(params.get("attach_mode") or "spawn")
        session_name = _runtime_session_name(params, default=f"root-{_safe_name(app_id)}")
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"runtime_bypass_root_{_safe_name(app_id)}_session.json",
        )
        payload = start_managed_runtime_session(
            case_dir=case_dir,
            name=session_name,
            app_id=app_id,
            session_kind="bypass_root",
            source_command="runtime bypass-root",
            builtin_script="root_bypass",
            script_label="root_bypass.js",
            device_id=device_id,
            attach_mode=attach_mode,
            metadata={"builtin_script": "root_bypass", "builtin_category": "evasion"},
            initial_wait_s=timeout,
            manager_factory=FridaManager,
        )
        if output is not None:
            write_json(output, payload)
            return _ok(payload, f"Managed root bypass session saved to {output}")
        return _ok(payload, f"Managed root bypass session {payload['session']['session_id']} is active")

    if action == "runtime.trace":
        app_id = _require(params, "app_id")
        class_name = _require(params, "class")
        method = _opt(params.get("method"))
        device_id = _opt(params.get("device_id"))
        timeout = float(params.get("timeout") or 1.0)
        case_dir = _require_runtime_case_dir(params)
        attach_mode = str(params.get("attach_mode") or "spawn")
        session_name = _runtime_session_name(params, default=f"trace-{_safe_name(app_id)}")
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"runtime_trace_{_safe_name(app_id)}_session.json",
        )
        payload = start_managed_runtime_session(
            case_dir=case_dir,
            name=session_name,
            app_id=app_id,
            session_kind="trace",
            source_command="runtime trace",
            script_source=method_tracer_script(class_name, method),
            script_label=f"trace_{_safe_name(class_name)}_{_safe_name(method or 'all')}.js",
            device_id=device_id,
            attach_mode=attach_mode,
            metadata={"class_name": class_name, "method": method},
            initial_wait_s=timeout,
            manager_factory=FridaManager,
        )
        if output is not None:
            write_json(output, payload)
            return _ok(payload, f"Managed trace session saved to {output}")
        return _ok(payload, f"Managed trace session {payload['session']['session_id']} is active")

    if action == "runtime.preflight":
        app_id = _require(params, "app_id")
        device_id = _opt(params.get("device_id"))
        attach_mode = str(params.get("attach_mode") or "spawn")
        session_kind = _opt(params.get("session_kind"))
        payload = runtime_preflight(
            app_id=app_id,
            device_id=device_id,
            attach_mode=attach_mode,
            session_kind=session_kind,
            manager_factory=FridaManager,
        )
        return _ok(payload, f"Runtime preflight finished with status {payload['status']}")

    if action == "runtime.sessions":
        case_dir = _require_runtime_case_dir(params)
        statuses = _csv_list(params.get("statuses")) or None
        session_kinds = _csv_list(params.get("session_kinds")) or None
        attach_modes = _csv_list(params.get("attach_modes")) or None
        query = _opt(params.get("query"))
        limit = int(params.get("limit") or 20)
        payload = list_managed_runtime_sessions(
            case_dir=case_dir,
            statuses=statuses,
            session_kinds=session_kinds,
            attach_modes=attach_modes,
            query=query,
            limit=limit,
        )
        return _ok(payload, f"Loaded {payload['session_count']} runtime sessions")

    if action == "runtime.session":
        case_dir = _require_runtime_case_dir(params)
        session_id = _require(params, "session_id")
        event_limit = int(params.get("event_limit") or 100)
        event_cursor_raw = params.get("event_cursor")
        event_cursor_text = str(event_cursor_raw) if event_cursor_raw not in {None, ""} else None
        payload = get_managed_runtime_session(
            case_dir=case_dir,
            session_id=session_id,
            event_limit=event_limit,
            event_cursor=int(event_cursor_text) if event_cursor_text is not None else None,
        )
        return _ok(payload, f"Loaded runtime session {session_id}")

    if action == "runtime.session_reload":
        case_dir = _require_runtime_case_dir(params)
        session_id = _require(params, "session_id")
        timeout = float(params.get("timeout") or 0.5)
        script = _opt(params.get("script"))
        payload = reload_managed_runtime_session(
            case_dir=case_dir,
            session_id=session_id,
            source_command="runtime session-reload",
            script_path=pathlib.Path(script) if script else None,
            builtin_script=_opt(params.get("builtin_script")),
            script_label=_opt(params.get("script_label")),
            initial_wait_s=timeout,
            manager_factory=FridaManager,
        )
        return _ok(payload, f"Reloaded runtime session {session_id}")

    if action == "runtime.session_reconnect":
        case_dir = _require_runtime_case_dir(params)
        session_id = _require(params, "session_id")
        attach_mode = _opt(params.get("attach_mode"))
        timeout = float(params.get("timeout") or 0.5)
        payload = reconnect_managed_runtime_session(
            case_dir=case_dir,
            session_id=session_id,
            attach_mode=attach_mode,
            initial_wait_s=timeout,
            manager_factory=FridaManager,
        )
        return _ok(payload, f"Reconnected runtime session {session_id}")

    if action == "runtime.session_stop":
        case_dir = _require_runtime_case_dir(params)
        session_id = _require(params, "session_id")
        payload = stop_managed_runtime_session(case_dir=case_dir, session_id=session_id)
        return _ok(payload, f"Stopped runtime session {session_id}")

    if action == "runtime.memory_search":
        app_id = _require(params, "app_id")
        pattern = _require(params, "pattern")
        is_hex = _bool_param(params.get("hex"))
        protection = str(params.get("protection") or "r--")
        timeout = float(params.get("timeout") or 30)
        device_id = _opt(params.get("device_id"))
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"runtime_memory_search_{_safe_name(app_id)}.json",
        )
        search_pattern = f"hex:{pattern}" if is_hex else pattern
        payload = json.loads(memory_search(app_id, search_pattern, device_id=device_id, protection=protection, timeout_s=timeout))
        if output is not None:
            write_json(output, payload)
            _register_case_output(
                case_dir,
                path=output,
                category="runtime-memory-search",
                source_command="runtime memory-search",
                device_serial=device_id,
                metadata={"app_id": app_id, "pattern": search_pattern, "protection": protection, "timeout_s": timeout},
            )
            return _ok(payload, f"Memory search saved to {output}")
        return _ok(payload, "Memory search complete")

    if action == "runtime.heap_dump":
        app_id = _require(params, "app_id")
        output_path = str(params.get("output") or "/sdcard/lockknife.hprof")
        timeout = float(params.get("timeout") or 30)
        device_id = _opt(params.get("device_id"))
        case_dir = _path_param(params.get("case_dir"))
        result_output, _derived = _resolve_case_output(
            _path_param(params.get("result_output")),
            case_dir,
            area="derived",
            filename=f"runtime_heap_dump_{_safe_name(app_id)}.json",
        )
        payload = json.loads(heap_dump(app_id, output_path, device_id=device_id, timeout_s=timeout))
        if result_output is not None:
            write_json(result_output, payload)
            _register_case_output(
                case_dir,
                path=result_output,
                category="runtime-heap-dump",
                source_command="runtime heap-dump",
                device_serial=device_id,
                metadata={"app_id": app_id, "remote_output_path": output_path, "timeout_s": timeout},
            )
            return _ok(payload, f"Heap dump result saved to {result_output}")
        return _ok(payload, "Heap dump complete")

    return None
