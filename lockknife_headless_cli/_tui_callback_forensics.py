from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast


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
    carve_deleted_files = cb.carve_deleted_files
    recover_deleted_records = cb.recover_deleted_records
    create_snapshot = cb.create_snapshot
    analyze_sqlite = cb.analyze_sqlite
    build_timeline = cb.build_timeline
    build_timeline_report = cb.build_timeline_report
    decode_protobuf_file = cb.decode_protobuf_file
    looks_like_aleapp_output = cb.looks_like_aleapp_output
    parse_forensics_directory = cb.parse_forensics_directory
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

    if action == "forensics.snapshot":
        serial = _require(params, "serial")
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="evidence",
            filename=f"snapshot_{serial}.tar",
        )
        if output is None:
            raise ValueError("Either output or case_dir is required")
        full = _bool_param(params.get("full"))
        encrypt = _bool_param(params.get("encrypt"))
        input_paths = _csv_list(params.get("paths"))
        out = create_snapshot(app.devices, serial, output_path=output, full=full, encrypt=encrypt)
        _register_case_output(
            case_dir,
            path=output,
            category="forensics-snapshot",
            source_command="forensics snapshot",
            device_serial=serial,
            input_paths=input_paths,
            metadata={"full": full, "encrypt": encrypt},
        )
        snapshot_artifact = (
            find_case_artifact(case_dir, path=output) if case_dir is not None else None
        )
        parent_ids = [snapshot_artifact.artifact_id] if snapshot_artifact is not None else None
        meta_path = output.with_suffix(output.suffix + ".meta.json")
        if meta_path.exists():
            _register_case_output(
                case_dir,
                path=meta_path,
                category="forensics-snapshot-meta",
                source_command="forensics snapshot",
                device_serial=serial,
                input_paths=input_paths,
                parent_artifact_ids=parent_ids,
                metadata={"full": full, "encrypt": encrypt},
            )
        key_path = output.with_suffix(output.suffix + ".key")
        if key_path.exists():
            _register_case_output(
                case_dir,
                path=key_path,
                category="forensics-snapshot-key",
                source_command="forensics snapshot",
                device_serial=serial,
                input_paths=input_paths,
                parent_artifact_ids=parent_ids,
                metadata={"full": full, "encrypt": encrypt},
            )
        return _ok(dataclasses.asdict(out), f"Snapshot written to {output}")

    def _parent_artifact_ids(case_dir: Any, input_paths: list[str]) -> list[str] | None:
        if case_dir is None:
            return None
        out: list[str] = []
        for input_path in input_paths:
            artifact = find_case_artifact(case_dir, path=pathlib.Path(input_path))
            if artifact is not None and artifact.artifact_id not in out:
                out.append(artifact.artifact_id)
        return out or None

    if action == "forensics.sqlite":
        path = pathlib.Path(_require(params, "path"))
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"sqlite_{path.stem}.json",
        )
        analysis = analyze_sqlite(path)
        payload = dataclasses.asdict(analysis)
        if output is not None:
            write_json(output, payload)
            input_paths = [str(path)]
            _register_case_output(
                case_dir,
                path=output,
                category="forensics-sqlite-analysis",
                source_command="forensics sqlite",
                input_paths=input_paths,
                parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
                metadata={
                    "table_count": len(analysis.tables),
                    "object_count": len(getattr(analysis, "objects", [])),
                },
            )
            return _ok(payload, f"SQLite analysis saved to {output}")
        return _ok(payload, f"SQLite tables: {len(analysis.tables)}")

    if action == "forensics.timeline":
        sms_path = _path_param(params.get("sms"))
        calls_path = _path_param(params.get("calls"))
        browser_path = _path_param(params.get("browser"))
        messaging_path = _path_param(params.get("messaging"))
        media_path = _path_param(params.get("media"))
        location_path = _path_param(params.get("location"))
        parsed_artifacts_path = _path_param(params.get("parsed_artifacts"))
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename="timeline.json",
        )
        payload = build_timeline_report(
            sms_path=sms_path,
            call_logs_path=calls_path,
            browser_path=browser_path,
            messaging_path=messaging_path,
            media_path=media_path,
            location_path=location_path,
            parsed_artifacts_path=parsed_artifacts_path,
            case_dir=case_dir,
        )
        if output is not None:
            write_json(output, payload)
            input_paths = [
                item["path"]
                for item in payload.get("sources", [])
                if isinstance(item, dict) and item.get("path")
            ]
            _register_case_output(
                case_dir,
                path=output,
                category="forensics-timeline",
                source_command="forensics timeline",
                input_paths=input_paths,
                parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
                metadata={
                    "event_count": payload.get("event_count", 0),
                    "source_count": len(payload.get("sources", [])),
                },
            )
            return _ok(payload, f"Wrote {payload.get('event_count', 0)} events to {output}")
        return _ok(payload, f"Built {payload.get('event_count', 0)} timeline events")

    if action == "forensics.parse":
        source_dir = (
            _path_param(params.get("path"))
            or _path_param(params.get("input_dir"))
            or _path_param(params.get("aleapp"))
        )
        if source_dir is None:
            raise ValueError("path, input_dir, or aleapp is required")
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename="parsed_artifacts.json",
        )
        report = parse_forensics_directory(source_dir)
        payload = dataclasses.asdict(report)
        if output is not None:
            write_json(output, payload)
            input_paths = [str(source_dir)] + [
                item["source_file"]
                for item in payload.get("artifacts", [])
                if isinstance(item, dict)
            ]
            _register_case_output(
                case_dir,
                path=output,
                category="forensics-parse",
                source_command="forensics parse",
                input_paths=input_paths,
                parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
                metadata={
                    "artifact_count": payload.get("summary", {}).get("artifact_count", 0),
                    "protobuf_count": payload.get("summary", {}).get("protobuf_count", 0),
                },
            )
            return _ok(payload, f"Parsed forensic artifacts saved to {output}")
        return _ok(
            payload, f"Parsed {payload.get('summary', {}).get('artifact_count', 0)} artifact groups"
        )

    if action == "forensics.import_aleapp":
        source_dir = _path_param(params.get("input_dir")) or _path_param(params.get("path"))
        if source_dir is None:
            raise ValueError("input_dir or path is required")
        if not looks_like_aleapp_output(source_dir):
            raise ValueError("Directory does not look like ALEAPP output")
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename="aleapp_import.json",
        )
        report = parse_forensics_directory(source_dir)
        payload = dataclasses.asdict(report)
        if output is not None:
            write_json(output, payload)
            input_paths = [str(source_dir)]
            _register_case_output(
                case_dir,
                path=output,
                category="forensics-aleapp-import",
                source_command="forensics import-aleapp",
                input_paths=input_paths,
                parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
                metadata={
                    "artifact_count": payload.get("summary", {}).get("artifact_count", 0),
                    "aleapp_imported_count": payload.get("summary", {}).get(
                        "aleapp_imported_count", 0
                    ),
                },
            )
            return _ok(payload, f"ALEAPP artifacts saved to {output}")
        return _ok(
            payload,
            f"Imported {payload.get('summary', {}).get('aleapp_imported_count', 0)} ALEAPP artifacts",
        )

    if action == "forensics.decode_protobuf":
        path = pathlib.Path(_require(params, "path"))
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"protobuf_{path.stem}.json",
        )
        payload = decode_protobuf_file(path)
        if payload is None:
            raise ValueError("Input does not appear to contain a decodable protobuf message")
        if output is not None:
            write_json(output, payload)
            input_paths = [str(path)]
            _register_case_output(
                case_dir,
                path=output,
                category="forensics-protobuf",
                source_command="forensics decode-protobuf",
                input_paths=input_paths,
                parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
                metadata={
                    "message_count": payload.get("message_count", 0),
                    "field_count": payload.get("field_count", 0),
                    "nested_message_count": payload.get("nested_message_count", 0),
                },
            )
            return _ok(payload, f"Decoded protobuf saved to {output}")
        return _ok(payload, f"Decoded {payload.get('message_count', 0)} protobuf fields")

    if action == "forensics.correlate":
        raw = _require(params, "inputs")
        paths = [pathlib.Path(p.strip()) for p in str(raw).split(",") if p.strip()]
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename="correlation.json",
        )
        blobs = [p.read_text(encoding="utf-8") for p in paths]
        payload = correlate_artifacts_json_blobs(blobs)
        if output is not None:
            write_json(output, payload)
            input_paths = [str(p) for p in paths]
            _register_case_output(
                case_dir,
                path=output,
                category="forensics-correlation",
                source_command="forensics correlate",
                input_paths=input_paths,
                parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
                metadata={"input_count": len(paths)},
            )
            return _ok(payload, f"Correlation saved to {output}")
        return _ok(payload, "Correlation complete")

    if action == "forensics.recover":
        path = pathlib.Path(_require(params, "path"))
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"recovered_{path.stem}.json",
        )
        payload = recover_deleted_records(path)
        if output is not None:
            write_json(output, payload)
            input_paths = [str(path)]
            _register_case_output(
                case_dir,
                path=output,
                category="forensics-recovery",
                source_command="forensics recover",
                input_paths=input_paths,
                parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
                metadata={
                    "fragment_count": len(payload.get("fragments", [])),
                    "high_confidence_count": payload.get("summary", {}).get(
                        "high_confidence_count", 0
                    ),
                },
            )
            return _ok(payload, f"Recovery saved to {output}")
        return _ok(payload, "Recovery complete")

    if action == "forensics.carve":
        path = pathlib.Path(_require(params, "path"))
        output_dir = pathlib.Path(_require(params, "output_dir"))
        source = str(params.get("source") or "auto").lower()
        max_matches = int(params.get("max_matches") or 25)
        case_dir = _path_param(params.get("case_dir"))
        payload = carve_deleted_files(path, output_dir, source=source, max_matches=max_matches)
        summary_path, _derived = _resolve_case_output(
            output_dir / f"carve_{path.stem}.json",
            case_dir,
            area="derived",
            filename=f"carve_{path.stem}.json",
        )
        if summary_path is not None:
            write_json(summary_path, payload)
            input_paths = [str(path)]
            _register_case_output(
                case_dir,
                path=summary_path,
                category="forensics-carve",
                source_command="forensics carve",
                input_paths=input_paths,
                parent_artifact_ids=_parent_artifact_ids(case_dir, input_paths),
                metadata={"carved_count": payload.get("carved_count", 0), "source": source},
            )
            return _ok(payload, f"Carving summary saved to {summary_path}")
        return _ok(payload, "Carving complete")

    return None
