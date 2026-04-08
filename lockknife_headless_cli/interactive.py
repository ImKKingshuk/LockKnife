from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any

import click
from rich.prompt import Prompt

from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules.apk.device_pull import pull_apk_from_device
from lockknife.modules.credentials.fido2 import pull_passkey_artifacts
from lockknife.modules.crypto_wallet.wallet import (
    enrich_wallet_addresses,
    extract_wallet_addresses_from_sqlite,
)
from lockknife.modules.extraction.browser import extract_chrome_history
from lockknife.modules.extraction.call_logs import extract_call_logs
from lockknife.modules.extraction.contacts import extract_contacts
from lockknife.modules.extraction.location import extract_location_artifacts
from lockknife.modules.extraction.media import extract_media_with_exif
from lockknife.modules.extraction.messaging import (
    extract_telegram_messages,
    extract_whatsapp_messages,
)
from lockknife.modules.extraction.sms import extract_sms
from lockknife.modules.forensics.correlation import correlate_artifacts_json_blobs
from lockknife.modules.forensics.recovery import recover_deleted_records
from lockknife.modules.forensics.snapshot import create_snapshot
from lockknife.modules.forensics.sqlite_analyzer import analyze_sqlite
from lockknife.modules.forensics.timeline import build_timeline
from lockknife.modules.intelligence.cve import correlate_cves_for_apk_package
from lockknife.modules.intelligence.otx import OtxError, indicator_reputation
from lockknife.modules.intelligence.virustotal import file_report
from lockknife.modules.network.api_discovery import extract_api_endpoints_from_pcap, summarize_pcap
from lockknife.modules.network.capture import capture_pcap
from lockknife.modules.security.bootloader import analyze_bootloader
from lockknife.modules.security.device_audit import run_device_audit
from lockknife.modules.security.hardware import analyze_hardware_security
from lockknife.modules.security.malware import scan_with_yara
from lockknife.modules.security.network_scan import scan_network
from lockknife.modules.security.selinux import get_selinux_status


@click.command()
@click.option("-s", "--serial")
@click.pass_obj
def interactive(app: Any, serial: str | None) -> None:
    console.print("LockKnife Interactive")
    while True:
        console.print(
            "\n".join(
                [
                    "",
                    "1  Device: list",
                    "2  Device: info",
                    "3  Extract: SMS",
                    "4  Extract: contacts",
                    "5  Extract: call logs",
                    "6  Extract: browser (Chrome history)",
                    "7  Extract: messaging (WhatsApp/Telegram)",
                    "8  Extract: media + EXIF",
                    "9  Extract: location artifacts",
                    "10 Forensics: snapshot",
                    "11 Forensics: SQLite analyzer",
                    "12 Forensics: timeline (from JSON files)",
                    "13 Security: device audit",
                    "14 Security: network scan",
                    "15 Security: SELinux status",
                    "16 Security: bootloader",
                    "17 Security: hardware",
                    "18 Credentials: passkeys export",
                    "19 Intel: reputation (VT/OTX/OSV)",
                    "20 APK: YARA scan (local or device pull)",
                    "21 Network: capture pcap (device)",
                    "22 Network: analyze pcap (local)",
                    "23 Network: API discovery (pcap)",
                    "24 Crypto wallet: extract + lookup",
                    "25 Forensics: correlate JSON artifacts",
                    "26 Forensics: recover deleted records (SQLite)",
                    "q  Quit",
                    "",
                ]
            )
        )
        choice = Prompt.ask(
            "Select",
            choices=[
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "8",
                "9",
                "10",
                "11",
                "12",
                "13",
                "14",
                "15",
                "16",
                "17",
                "18",
                "19",
                "20",
                "21",
                "22",
                "23",
                "24",
                "25",
                "26",
                "q",
            ],
            default="q",
        )
        if choice == "q":
            return
        if choice == "1":
            devices = app.devices.list()
            for d in devices:
                console.print(d.serial)
            continue
        if choice == "2":
            s = serial or Prompt.ask("Device serial")
            info = app.devices.info(s)
            console.print_json(json.dumps(dataclasses.asdict(info)))
            continue
        if choice == "3":
            s = serial or Prompt.ask("Device serial")
            limit = int(Prompt.ask("Limit", default="50"))
            msgs = extract_sms(app.devices, s, limit=limit)
            console.print_json(json.dumps([dataclasses.asdict(m) for m in msgs]))
            continue
        if choice == "4":
            s = serial or Prompt.ask("Device serial")
            limit = int(Prompt.ask("Limit", default="50"))
            contact_rows = extract_contacts(app.devices, s, limit=limit)
            console.print_json(json.dumps([dataclasses.asdict(r) for r in contact_rows]))
            continue
        if choice == "5":
            s = serial or Prompt.ask("Device serial")
            limit = int(Prompt.ask("Limit", default="50"))
            call_log_rows = extract_call_logs(app.devices, s, limit=limit)
            console.print_json(json.dumps([dataclasses.asdict(r) for r in call_log_rows]))
            continue
        if choice == "6":
            s = serial or Prompt.ask("Device serial")
            limit = int(Prompt.ask("Limit", default="50"))
            browser_rows = extract_chrome_history(app.devices, s, limit=limit)
            console.print_json(json.dumps([dataclasses.asdict(r) for r in browser_rows]))
            continue
        if choice == "7":
            s = serial or Prompt.ask("Device serial")
            app_name = Prompt.ask("App", choices=["whatsapp", "telegram"], default="whatsapp")
            limit = int(Prompt.ask("Limit", default="50"))
            if app_name == "telegram":
                message_payload = [
                    dataclasses.asdict(r)
                    for r in extract_telegram_messages(app.devices, s, limit=limit)
                ]
            else:
                message_payload = [
                    dataclasses.asdict(r)
                    for r in extract_whatsapp_messages(app.devices, s, limit=limit)
                ]
            console.print_json(json.dumps(message_payload))
            continue
        if choice == "8":
            s = serial or Prompt.ask("Device serial")
            limit = int(Prompt.ask("Limit", default="20"))
            media_rows = extract_media_with_exif(app.devices, s, limit=limit)
            console.print_json(json.dumps([dataclasses.asdict(r) for r in media_rows]))
            continue
        if choice == "9":
            s = serial or Prompt.ask("Device serial")
            location_payload = dataclasses.asdict(extract_location_artifacts(app.devices, s))
            console.print_json(json.dumps(location_payload))
            continue
        if choice == "10":
            s = serial or Prompt.ask("Device serial")
            output = pathlib.Path(Prompt.ask("Output path", default="snapshot.tar"))
            full = Prompt.ask("Full snapshot?", choices=["y", "n"], default="n") == "y"
            encrypt = Prompt.ask("Encrypt?", choices=["y", "n"], default="n") == "y"
            out = create_snapshot(app.devices, s, output_path=output, full=full, encrypt=encrypt)
            console.print(str(out))
            continue
        if choice == "11":
            sqlite_path = pathlib.Path(Prompt.ask("SQLite path"))
            analysis = analyze_sqlite(sqlite_path)
            console.print(f"Tables: {len(analysis.tables)}")
            continue
        if choice == "12":
            sms_path = Prompt.ask("SMS JSON path")
            call_path = Prompt.ask("Call logs JSON path")
            out_path = Prompt.ask("Output JSON path", default="timeline.json")
            sms_rows = json.loads(pathlib.Path(sms_path).read_text(encoding="utf-8"))
            call_rows = json.loads(pathlib.Path(call_path).read_text(encoding="utf-8"))
            events = [
                dataclasses.asdict(e) for e in build_timeline(sms=sms_rows, call_logs=call_rows)
            ]
            write_json(pathlib.Path(out_path), events)
            console.print(f"Wrote {len(events)} events to {out_path}")
            continue
        if choice == "13":
            s = serial or Prompt.ask("Device serial")
            findings = [dataclasses.asdict(f) for f in run_device_audit(app.devices, s)]
            console.print_json(json.dumps(findings))
            continue
        if choice == "14":
            s = serial or Prompt.ask("Device serial")
            scan = scan_network(app.devices, s)
            network_payload = {
                "dns": scan.dns,
                "dns_cache": scan.dns_cache,
                "listening": [dataclasses.asdict(item) for item in scan.listening],
            }
            console.print_json(json.dumps(network_payload))
            continue
        if choice == "15":
            s = serial or Prompt.ask("Device serial")
            selinux_status = get_selinux_status(app.devices, s)
            console.print_json(json.dumps(dataclasses.asdict(selinux_status)))
            continue
        if choice == "16":
            s = serial or Prompt.ask("Device serial")
            bootloader_status = analyze_bootloader(app.devices, s)
            console.print_json(json.dumps(dataclasses.asdict(bootloader_status)))
            continue
        if choice == "17":
            s = serial or Prompt.ask("Device serial")
            hardware_status = analyze_hardware_security(app.devices, s)
            console.print_json(json.dumps(dataclasses.asdict(hardware_status)))
            continue
        if choice == "18":
            s = serial or Prompt.ask("Device serial")
            out_dir = pathlib.Path(Prompt.ask("Output directory", default="passkeys"))
            limit = int(Prompt.ask("Max files", default="200"))
            items = [
                dataclasses.asdict(x)
                for x in pull_passkey_artifacts(app.devices, s, output_dir=out_dir, limit=limit)
            ]
            console.print_json(json.dumps(items))
            continue
        if choice == "19":
            kind = Prompt.ask(
                "Indicator type", choices=["hash", "domain", "ip", "package"], default="hash"
            )
            indicator_payload: dict[str, object] = {}
            combined_score = 0
            if kind == "hash":
                h = Prompt.ask("SHA256")
                try:
                    vt = file_report(h)
                    indicator_payload["virustotal"] = vt
                    stats = (
                        (vt.get("attributes") or {}).get("last_analysis_stats")
                        if isinstance(vt, dict)
                        else None
                    )
                    if isinstance(stats, dict):
                        malicious = int(stats.get("malicious") or 0)
                        suspicious = int(stats.get("suspicious") or 0)
                        combined_score += malicious * 10 + suspicious * 5
                except Exception as e:
                    indicator_payload["virustotal_error"] = str(e)
                try:
                    indicator_payload["otx"] = indicator_reputation(h)
                except OtxError as e:
                    indicator_payload["otx_error"] = str(e)
            elif kind == "domain":
                d = Prompt.ask("Domain")
                try:
                    indicator_payload["otx"] = indicator_reputation(d)
                except OtxError as e:
                    indicator_payload["otx_error"] = str(e)
            elif kind == "ip":
                ip = Prompt.ask("IP")
                try:
                    indicator_payload["otx"] = indicator_reputation(ip)
                except OtxError as e:
                    indicator_payload["otx_error"] = str(e)
            else:
                pkg = Prompt.ask("Package name")
                try:
                    indicator_payload["osv"] = correlate_cves_for_apk_package(pkg)
                except Exception as e:
                    indicator_payload["osv_error"] = str(e)
            indicator_payload["combined_score"] = combined_score
            console.print_json(json.dumps(indicator_payload))
            continue
        if choice == "20":
            yara_rule = pathlib.Path(Prompt.ask("YARA rule path"))
            mode = Prompt.ask("Target mode", choices=["local", "device"], default="local")
            target: pathlib.Path | None = None
            package_name: str | None = None
            if mode == "device":
                s = serial or Prompt.ask("Device serial")
                package_name = Prompt.ask("Package name")
                target = pull_apk_from_device(app.devices, s, package_name)
            else:
                target = pathlib.Path(Prompt.ask("APK path"))
            if target is None:
                raise click.ClickException("APK target is required")
            matches = [dataclasses.asdict(m) for m in scan_with_yara(yara_rule, target)]
            console.print_json(
                json.dumps(
                    {
                        "apk": str(target),
                        "package": package_name,
                        "engine": "yara",
                        "matches": matches,
                    }
                )
            )
            continue
        if choice == "21":
            s = serial or Prompt.ask("Device serial")
            output = pathlib.Path(Prompt.ask("Output pcap path", default="capture.pcap"))
            duration = float(Prompt.ask("Duration seconds", default="30"))
            iface = Prompt.ask("Interface", default="any")
            result = dataclasses.asdict(
                capture_pcap(app.devices, s, output_path=output, duration_s=duration, iface=iface)
            )
            console.print_json(json.dumps(result))
            continue
        if choice == "22":
            pcap_path = pathlib.Path(Prompt.ask("PCAP path"))
            pcap_summary = summarize_pcap(pcap_path)
            console.print_json(json.dumps(pcap_summary))
            continue
        if choice == "23":
            pcap_path = pathlib.Path(Prompt.ask("PCAP path"))
            api_payload = extract_api_endpoints_from_pcap(pcap_path)
            console.print_json(json.dumps(api_payload))
            continue
        if choice == "24":
            wallet_db_path = pathlib.Path(Prompt.ask("SQLite wallet DB path"))
            do_lookup = Prompt.ask("Lookup balances?", choices=["y", "n"], default="n") == "y"
            addrs = extract_wallet_addresses_from_sqlite(wallet_db_path)
            if do_lookup:
                wallet_rows: Any = enrich_wallet_addresses(addrs)
            else:
                wallet_rows = [dataclasses.asdict(r) for r in addrs]
            console.print_json(json.dumps(wallet_rows))
            continue
        if choice == "25":
            paths = Prompt.ask("JSON artifact paths (comma-separated)")
            inputs = [pathlib.Path(x.strip()) for x in paths.split(",") if x.strip()]
            blobs = [p.read_text(encoding="utf-8") for p in inputs]
            correlation_payload = correlate_artifacts_json_blobs(blobs)
            console.print_json(json.dumps(correlation_payload))
            continue
        if choice == "26":
            recovery_db_path = pathlib.Path(Prompt.ask("SQLite DB path"))
            recovery_payload = recover_deleted_records(recovery_db_path)
            console.print_json(json.dumps(recovery_payload))
            continue
