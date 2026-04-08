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
    recover_deleted_records = cb.recover_deleted_records
    create_snapshot = cb.create_snapshot
    analyze_sqlite = cb.analyze_sqlite
    build_timeline = cb.build_timeline
    android_cve_risk_score = cb.android_cve_risk_score
    correlate_cves_for_apk_package = cb.correlate_cves_for_apk_package
    correlate_cves_for_kernel_version = cb.correlate_cves_for_kernel_version
    detect_iocs = cb.detect_iocs
    load_stix_indicators_from_url = cb.load_stix_indicators_from_url
    load_taxii_indicators = cb.load_taxii_indicators
    indicator_reputation = cb.indicator_reputation
    domain_report = cb.domain_report
    file_report = cb.file_report
    ip_report = cb.ip_report
    submit_url_for_analysis = cb.submit_url_for_analysis
    url_report = cb.url_report
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

    if action == "intelligence.ioc":
        path = pathlib.Path(_require(params, "input"))
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"intel_ioc_{_safe_name(path.stem)}.json",
        )
        data = json.loads(path.read_text(encoding="utf-8"))
        rules_path = _path_param(params.get("composite_rules"))
        rules: list[dict[str, Any]] | None = None
        if rules_path is not None:
            parsed_rules = json.loads(rules_path.read_text(encoding="utf-8"))
            if isinstance(parsed_rules, list):
                rules = [item for item in parsed_rules if isinstance(item, dict)]
        matches = [dataclasses.asdict(m) for m in detect_iocs(data, composite_rules=rules)]
        payload = ioc_payload(matches, input_path=path, case_dir=case_dir, output=output)
        if output is not None:
            write_json(output, payload)
            _register_case_output(
                case_dir,
                path=output,
                category="intel-ioc",
                source_command="intel ioc",
                input_paths=[str(path)],
                metadata=payload.get("summary"),
            )
            return _ok(payload, f"IOC matches saved to {output}")
        return _ok(payload, f"IOC matches: {len(matches)}")

    if action == "intelligence.cve":
        package = _require(params, "package")
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"intel_cve_{_safe_name(package)}.json",
        )
        payload = cve_payload(
            package, correlate_cves_for_apk_package(package), case_dir=case_dir, output=output
        )
        if output is not None:
            write_json(output, payload)
            _register_case_output(
                case_dir,
                path=output,
                category="intel-cve",
                source_command="intel cve",
                metadata=payload.get("summary"),
            )
            return _ok(payload, f"CVE correlation saved to {output}")
        return _ok(payload, "CVE correlation complete")

    if action == "intelligence.virustotal":
        file_hash = _opt(params.get("hash"))
        url_value = _opt(params.get("url"))
        domain = _opt(params.get("domain"))
        ip_address = _opt(params.get("ip"))
        submit_url = _opt(params.get("submit_url"))
        selected = [("file", file_hash), ("url", url_value), ("domain", domain), ("ip", ip_address)]
        populated = [(kind, value) for kind, value in selected if value]
        if submit_url:
            if populated:
                raise ValueError("Use submit_url by itself")
            indicator_type, indicator = "url", submit_url
            vt_data = submit_url_for_analysis(submit_url)
        else:
            if len(populated) != 1:
                raise ValueError("Provide exactly one of hash, url, domain, or ip")
            indicator_type, indicator = populated[0]
            if indicator_type == "file":
                vt_data = file_report(str(indicator))
            elif indicator_type == "url":
                vt_data = url_report(str(indicator))
            elif indicator_type == "domain":
                vt_data = domain_report(str(indicator))
            else:
                vt_data = ip_report(str(indicator))
        if indicator is None:
            raise ValueError("Indicator is required")
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"intel_virustotal_{_safe_name(str(indicator)[:32])}.json",
        )
        payload = virustotal_payload(
            str(indicator), vt_data, indicator_type=indicator_type, case_dir=case_dir, output=output
        )
        if output is not None:
            write_json(output, payload)
            _register_case_output(
                case_dir,
                path=output,
                category="intel-virustotal",
                source_command="intel virustotal",
                metadata=payload.get("summary"),
            )
            return _ok(payload, f"VirusTotal report saved to {output}")
        return _ok(payload, "VirusTotal report fetched")

    if action == "intelligence.cve_risk":
        sdk_raw = _opt(params.get("sdk"))
        kernel_version = _opt(params.get("kernel_version"))
        if not sdk_raw and not kernel_version:
            raise ValueError("sdk or kernel_version is required")
        sdk = int(sdk_raw) if sdk_raw else None
        risk_payload: dict[str, Any] = {}
        if sdk is not None:
            risk_payload["android"] = android_cve_risk_score(sdk)
        if kernel_version:
            risk_payload["kernel"] = correlate_cves_for_kernel_version(kernel_version)
        android_data = risk_payload.get("android")
        kernel_data = risk_payload.get("kernel")
        risk_payload["summary"] = {
            "sdk": sdk,
            "kernel_version": kernel_version,
            "max_score": max(
                int(android_data.get("score") or 0) if isinstance(android_data, dict) else 0,
                int(kernel_data.get("score") or 0) if isinstance(kernel_data, dict) else 0,
            ),
        }
        case_dir = _path_param(params.get("case_dir"))
        filename = f"intel_cve_risk_{_safe_name(kernel_version or f'sdk_{sdk}')}.json"
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")), case_dir, area="derived", filename=filename
        )
        if output is not None:
            write_json(output, risk_payload)
            _register_case_output(
                case_dir,
                path=output,
                category="intel-cve-risk",
                source_command="intel cve-risk",
                metadata=risk_payload.get("summary"),
            )
            return _ok(risk_payload, f"CVE risk saved to {output}")
        return _ok(risk_payload, "CVE risk profiled")

    if action == "intelligence.otx":
        indicator = _require(params, "indicator")
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"intel_otx_{_safe_name(indicator)}.json",
        )
        payload = otx_payload(
            indicator, indicator_reputation(indicator), case_dir=case_dir, output=output
        )
        if output is not None:
            write_json(output, payload)
            _register_case_output(
                case_dir,
                path=output,
                category="intel-otx",
                source_command="intel otx",
                metadata=payload.get("summary"),
            )
            return _ok(payload, f"OTX reputation saved to {output}")
        return _ok(payload, "OTX reputation fetched")

    if action == "intelligence.stix":
        url = _require(params, "url")
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename="intel_stix.json",
        )
        matches = [dataclasses.asdict(m) for m in load_stix_indicators_from_url(url)]
        payload = stix_payload(url, matches, case_dir=case_dir, output=output)
        if output is not None:
            write_json(output, payload)
            _register_case_output(
                case_dir,
                path=output,
                category="intel-stix",
                source_command="intel stix",
                metadata=payload.get("summary"),
            )
            return _ok(payload, f"STIX indicators saved to {output}")
        return _ok(payload, f"STIX indicators: {len(matches)}")

    if action == "intelligence.taxii":
        api_root = _require(params, "api_root")
        collection_id = _opt(params.get("collection_id"))
        token = _opt(params.get("token"))
        username = _opt(params.get("username"))
        password = _opt(params.get("password"))
        added_after = _opt(params.get("added_after"))
        limit = int(params.get("limit") or 2000)
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename="intel_taxii.json",
        )
        matches = [
            dataclasses.asdict(m)
            for m in load_taxii_indicators(
                api_root,
                collection_id=collection_id,
                added_after=added_after,
                token=token,
                username=username,
                password=password,
                limit=limit,
            )
        ]
        payload = taxii_payload(
            api_root,
            matches,
            collection_id=collection_id,
            limit=limit,
            token=token,
            username=username,
            password=password,
            case_dir=case_dir,
            output=output,
        )
        if output is not None:
            write_json(output, payload)
            _register_case_output(
                case_dir,
                path=output,
                category="intel-taxii",
                source_command="intel taxii",
                metadata=payload.get("summary"),
            )
            return _ok(payload, f"TAXII indicators saved to {output}")
        return _ok(payload, f"TAXII indicators: {len(matches)}")

    return None
