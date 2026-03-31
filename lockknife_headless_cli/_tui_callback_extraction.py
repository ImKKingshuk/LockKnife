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

    if action == "extraction.sms":
        serial = _require(params, "serial")
        limit = int(params.get("limit") or 200)
        out_format = str(params.get("format") or "json").lower()
        ext = "csv" if out_format == "csv" else "json"
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="evidence",
            filename=f"sms.{ext}",
        )
        sms_rows = [dataclasses.asdict(r) for r in extract_sms(app.devices, serial, limit=limit)]
        if output is not None:
            if ext == "csv":
                write_csv(output, sms_rows)
            else:
                write_json(output, sms_rows)
            _register_case_output(
                case_dir,
                path=output,
                category="extract-sms",
                source_command="extract sms",
                device_serial=serial,
                metadata={"format": ext, "limit": limit},
            )
            return _ok(sms_rows, f"Extracted {len(sms_rows)} SMS messages to {output}")
        return _ok(sms_rows, f"Extracted {len(sms_rows)} SMS messages")

    if action == "extraction.contacts":
        serial = _require(params, "serial")
        limit = int(params.get("limit") or 200)
        out_format = str(params.get("format") or "json").lower()
        ext = "csv" if out_format == "csv" else "json"
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="evidence",
            filename=f"contacts.{ext}",
        )
        contact_rows = [dataclasses.asdict(r) for r in extract_contacts(app.devices, serial, limit=limit)]
        if output is not None:
            if ext == "csv":
                write_csv(output, contact_rows)
            else:
                write_json(output, contact_rows)
            _register_case_output(
                case_dir,
                path=output,
                category="extract-contacts",
                source_command="extract contacts",
                device_serial=serial,
                metadata={"format": ext, "limit": limit},
            )
            return _ok(contact_rows, f"Extracted {len(contact_rows)} contacts to {output}")
        return _ok(contact_rows, f"Extracted {len(contact_rows)} contacts")

    if action == "extraction.call_logs":
        serial = _require(params, "serial")
        limit = int(params.get("limit") or 200)
        out_format = str(params.get("format") or "json").lower()
        ext = "csv" if out_format == "csv" else "json"
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="evidence",
            filename=f"call_logs.{ext}",
        )
        call_log_rows = [dataclasses.asdict(r) for r in extract_call_logs(app.devices, serial, limit=limit)]
        if output is not None:
            if ext == "csv":
                write_csv(output, call_log_rows)
            else:
                write_json(output, call_log_rows)
            _register_case_output(
                case_dir,
                path=output,
                category="extract-call-logs",
                source_command="extract call-logs",
                device_serial=serial,
                metadata={"format": ext, "limit": limit},
            )
            return _ok(call_log_rows, f"Extracted {len(call_log_rows)} call logs to {output}")
        return _ok(call_log_rows, f"Extracted {len(call_log_rows)} call logs")

    if action == "extraction.browser":
        serial = _require(params, "serial")
        app_name = str(params.get("app") or "chrome").lower()
        kind = str(params.get("kind") or "history").lower()
        limit = int(params.get("limit") or 200)
        out_format = str(params.get("format") or "json").lower()
        ext = "csv" if out_format == "csv" else "json"
        if kind == "all" and ext != "json":
            raise ValueError("CSV is not supported when browser kind is 'all'")
        case_dir = _path_param(params.get("case_dir"))
        browser_filename = f"browser_{app_name}.{ext}" if kind == "all" else f"browser_{app_name}_{kind}.{ext}"
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="evidence",
            filename=browser_filename,
        )
        if kind == "all":
            if app_name == "firefox":
                payload = {
                    "app": "firefox",
                    "history": [dataclasses.asdict(r) for r in extract_firefox_history(app.devices, serial, limit=limit)],
                    "bookmarks": [dataclasses.asdict(r) for r in extract_firefox_bookmarks(app.devices, serial, limit=limit)],
                    "passwords": [dataclasses.asdict(r) for r in extract_firefox_saved_logins(app.devices, serial, limit=limit)],
                }
            else:
                payload = {
                    "app": app_name,
                    "history": [dataclasses.asdict(r) for r in extract_chrome_history(app.devices, serial, limit=limit, browser=app_name)],
                    "bookmarks": [dataclasses.asdict(r) for r in extract_chrome_bookmarks(app.devices, serial, limit=limit, browser=app_name)],
                    "downloads": [dataclasses.asdict(r) for r in extract_chrome_downloads(app.devices, serial, limit=limit, browser=app_name)],
                    "cookies": [dataclasses.asdict(r) for r in extract_chrome_cookies(app.devices, serial, limit=limit, browser=app_name)],
                    "passwords": [dataclasses.asdict(r) for r in extract_chrome_saved_logins(app.devices, serial, limit=limit, browser=app_name)],
                }
            if output is not None:
                write_json(output, payload)
                _register_case_output(
                    case_dir,
                    path=output,
                    category="extract-browser",
                    source_command="extract browser",
                    device_serial=serial,
                    metadata={"app": app_name, "kind": kind, "format": ext, "limit": limit},
                )
                return _ok(payload, f"Extracted browser records to {output}")
            return _ok(payload, "Extracted browser records")
        rows: list[Any] = []
        if app_name == "firefox":
            if kind in {"bookmarks", "all"}:
                rows.extend(dataclasses.asdict(r) for r in extract_firefox_bookmarks(app.devices, serial, limit=limit))
            if kind in {"passwords", "all"}:
                rows.extend(dataclasses.asdict(r) for r in extract_firefox_saved_logins(app.devices, serial, limit=limit))
            if kind in {"history", "all"}:
                rows.extend(dataclasses.asdict(r) for r in extract_firefox_history(app.devices, serial, limit=limit))
        else:
            if kind in {"bookmarks", "all"}:
                rows.extend(dataclasses.asdict(r) for r in extract_chrome_bookmarks(app.devices, serial, limit=limit, browser=app_name))
            if kind in {"downloads", "all"}:
                rows.extend(dataclasses.asdict(r) for r in extract_chrome_downloads(app.devices, serial, limit=limit, browser=app_name))
            if kind in {"cookies", "all"}:
                rows.extend(dataclasses.asdict(r) for r in extract_chrome_cookies(app.devices, serial, limit=limit, browser=app_name))
            if kind in {"passwords", "all"}:
                rows.extend(dataclasses.asdict(r) for r in extract_chrome_saved_logins(app.devices, serial, limit=limit, browser=app_name))
            if kind in {"history", "all"}:
                rows.extend(dataclasses.asdict(r) for r in extract_chrome_history(app.devices, serial, limit=limit, browser=app_name))
        if output is not None:
            if ext == "csv":
                write_csv(output, rows)
            else:
                write_json(output, rows)
            _register_case_output(
                case_dir,
                path=output,
                category="extract-browser",
                source_command="extract browser",
                device_serial=serial,
                metadata={"app": app_name, "kind": kind, "format": ext, "limit": limit},
            )
            return _ok(rows, f"Extracted {len(rows)} browser records to {output}")
        return _ok(rows, f"Extracted {len(rows)} browser records")

    if action == "extraction.messaging":
        serial = _require(params, "serial")
        app_name = str(params.get("app") or "whatsapp").lower()
        mode = str(params.get("mode") or "messages").lower()
        limit = int(params.get("limit") or 200)
        out_format = str(params.get("format") or "json").lower()
        ext = "csv" if out_format == "csv" else "json"
        if mode == "artifacts" and ext != "json":
            raise ValueError("CSV is not supported when messaging mode is 'artifacts'")
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="evidence",
            filename=f"messaging_{app_name}_{mode}.{ext}",
        )
        if mode == "artifacts":
            if app_name == "telegram":
                payload = dataclasses.asdict(extract_telegram_artifacts(app.devices, serial))
            elif app_name == "signal":
                payload = dataclasses.asdict(extract_signal_artifacts(app.devices, serial))
            else:
                payload = dataclasses.asdict(extract_whatsapp_artifacts(app.devices, serial))
            if output is not None:
                write_json(output, payload)
                _register_case_output(
                    case_dir,
                    path=output,
                    category="extract-messaging",
                    source_command="extract messaging",
                    device_serial=serial,
                    metadata={"app": app_name, "mode": mode, "format": ext, "limit": limit},
                )
                return _ok(payload, f"Extracted messaging artifacts to {output}")
            return _ok(payload, "Extracted messaging artifacts")
        if app_name == "telegram":
            rows = [dataclasses.asdict(r) for r in extract_telegram_messages(app.devices, serial, limit=limit)]
        elif app_name == "signal":
            rows = [dataclasses.asdict(r) for r in extract_signal_messages(app.devices, serial, limit=limit)]
        else:
            rows = [dataclasses.asdict(r) for r in extract_whatsapp_messages(app.devices, serial, limit=limit)]
        if output is not None:
            if ext == "csv":
                write_csv(output, rows)
            else:
                write_json(output, rows)
            _register_case_output(
                case_dir,
                path=output,
                category="extract-messaging",
                source_command="extract messaging",
                device_serial=serial,
                metadata={"app": app_name, "mode": mode, "format": ext, "limit": limit},
            )
            return _ok(rows, f"Extracted {len(rows)} messages to {output}")
        return _ok(rows, f"Extracted {len(rows)} messages")

    if action == "extraction.media":
        serial = _require(params, "serial")
        limit = int(params.get("limit") or 20)
        out_format = str(params.get("format") or "json").lower()
        ext = "csv" if out_format == "csv" else "json"
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="evidence",
            filename=f"media.{ext}",
        )
        rows = [dataclasses.asdict(r) for r in extract_media_with_exif(app.devices, serial, limit=limit)]
        if output is not None:
            if ext == "csv":
                write_csv(output, rows)
            else:
                write_json(output, rows)
            _register_case_output(
                case_dir,
                path=output,
                category="extract-media",
                source_command="extract media",
                device_serial=serial,
                metadata={"format": ext, "limit": limit},
            )
            return _ok(rows, f"Extracted {len(rows)} media records to {output}")
        return _ok(rows, f"Extracted {len(rows)} media records")

    if action == "extraction.location":
        serial = _require(params, "serial")
        mode = str(params.get("mode") or "artifacts").lower()
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="evidence",
            filename=f"location_{mode}.json",
        )
        if mode == "snapshot":
            payload = dataclasses.asdict(extract_location_snapshot(app.devices, serial))
        else:
            payload = dataclasses.asdict(extract_location_artifacts(app.devices, serial))
        if output is not None:
            write_json(output, payload)
            _register_case_output(
                case_dir,
                path=output,
                category="extract-location",
                source_command="extract location",
                device_serial=serial,
                metadata={"mode": mode, "format": "json"},
            )
            return _ok(payload, f"Location artifacts saved to {output}")
        return _ok(payload, "Location artifacts extracted")

    if action == "extraction.all":
        serial = _require(params, "serial")
        limit = int(params.get("limit") or 200)
        out_format = str(params.get("format") or "json").lower()
        case_dir = _path_param(params.get("case_dir"))
        output_dir = _path_param(params.get("output_dir"))
        ext = "csv" if out_format == "csv" else "json"
        results: dict[str, Any] = {"serial": serial, "artifacts": {}}
        artifact_ids: list[str] = []
        
        # Extract SMS
        try:
            sms_rows = [dataclasses.asdict(r) for r in extract_sms(app.devices, serial, limit=limit)]
            results["artifacts"]["sms"] = {"count": len(sms_rows), "rows": sms_rows}
            if output_dir is not None and case_dir is not None:
                sms_path = output_dir / f"sms.{ext}"
                if ext == "csv":
                    write_csv(sms_path, sms_rows)
                else:
                    write_json(sms_path, sms_rows)
                aid = _register_case_output(
                    case_dir,
                    path=sms_path,
                    category="extract-sms",
                    source_command="extract all",
                    device_serial=serial,
                    metadata={"format": ext, "limit": limit},
                )
                if aid:
                    artifact_ids.append(aid)
        except Exception as e:
            results["artifacts"]["sms"] = {"error": str(e)}
        
        # Extract Contacts
        try:
            contact_rows = [dataclasses.asdict(r) for r in extract_contacts(app.devices, serial, limit=limit)]
            results["artifacts"]["contacts"] = {"count": len(contact_rows), "rows": contact_rows}
            if output_dir is not None and case_dir is not None:
                contacts_path = output_dir / f"contacts.{ext}"
                if ext == "csv":
                    write_csv(contacts_path, contact_rows)
                else:
                    write_json(contacts_path, contact_rows)
                aid = _register_case_output(
                    case_dir,
                    path=contacts_path,
                    category="extract-contacts",
                    source_command="extract all",
                    device_serial=serial,
                    metadata={"format": ext, "limit": limit},
                )
                if aid:
                    artifact_ids.append(aid)
        except Exception as e:
            results["artifacts"]["contacts"] = {"error": str(e)}
        
        # Extract Call Logs
        try:
            call_log_rows = [dataclasses.asdict(r) for r in extract_call_logs(app.devices, serial, limit=limit)]
            results["artifacts"]["call_logs"] = {"count": len(call_log_rows), "rows": call_log_rows}
            if output_dir is not None and case_dir is not None:
                calls_path = output_dir / f"call_logs.{ext}"
                if ext == "csv":
                    write_csv(calls_path, call_log_rows)
                else:
                    write_json(calls_path, call_log_rows)
                aid = _register_case_output(
                    case_dir,
                    path=calls_path,
                    category="extract-call-logs",
                    source_command="extract all",
                    device_serial=serial,
                    metadata={"format": ext, "limit": limit},
                )
                if aid:
                    artifact_ids.append(aid)
        except Exception as e:
            results["artifacts"]["call_logs"] = {"error": str(e)}
        
        # Extract Chrome History
        try:
            history_rows = [dataclasses.asdict(r) for r in extract_chrome_history(app.devices, serial, limit=limit)]
            results["artifacts"]["chrome_history"] = {"count": len(history_rows), "rows": history_rows}
            if output_dir is not None and case_dir is not None:
                history_path = output_dir / f"chrome_history.{ext}"
                if ext == "csv":
                    write_csv(history_path, history_rows)
                else:
                    write_json(history_path, history_rows)
                aid = _register_case_output(
                    case_dir,
                    path=history_path,
                    category="extract-browser",
                    source_command="extract all",
                    device_serial=serial,
                    metadata={"app": "chrome", "kind": "history", "format": ext, "limit": limit},
                )
                if aid:
                    artifact_ids.append(aid)
        except Exception as e:
            results["artifacts"]["chrome_history"] = {"error": str(e)}
        
        # Extract Media
        try:
            media_rows = [dataclasses.asdict(r) for r in extract_media_with_exif(app.devices, serial, limit=limit)]
            results["artifacts"]["media"] = {"count": len(media_rows), "rows": media_rows}
            if output_dir is not None and case_dir is not None:
                media_path = output_dir / f"media.{ext}"
                if ext == "csv":
                    write_csv(media_path, media_rows)
                else:
                    write_json(media_path, media_rows)
                aid = _register_case_output(
                    case_dir,
                    path=media_path,
                    category="extract-media",
                    source_command="extract all",
                    device_serial=serial,
                    metadata={"format": ext, "limit": limit},
                )
                if aid:
                    artifact_ids.append(aid)
        except Exception as e:
            results["artifacts"]["media"] = {"error": str(e)}
        
        # Extract Location
        try:
            location = dataclasses.asdict(extract_location_artifacts(app.devices, serial))
            results["artifacts"]["location"] = location
            if output_dir is not None and case_dir is not None:
                location_path = output_dir / "location.json"
                write_json(location_path, location)
                aid = _register_case_output(
                    case_dir,
                    path=location_path,
                    category="extract-location",
                    source_command="extract all",
                    device_serial=serial,
                    metadata={"format": "json"},
                )
                if aid:
                    artifact_ids.append(aid)
        except Exception as e:
            results["artifacts"]["location"] = {"error": str(e)}
        
        total_count = sum(
            v.get("count", 0) for v in results["artifacts"].values() 
            if isinstance(v, dict) and "count" in v
        )
        results["total_count"] = total_count
        results["artifact_ids"] = artifact_ids
        
        return _ok(results, f"Extracted {total_count} total artifacts across {len(results['artifacts'])} categories")

    return None
