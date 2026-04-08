from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from lockknife_headless_cli._credential_workflows import (
    run_gesture_recovery_workflow,
    run_keystore_workflow,
    run_passkey_workflow,
    run_pin_recovery_workflow,
    run_wifi_workflow,
)


def handle(app: Any, action: str, params: dict[str, object], *, cb: Any) -> dict[str, Any] | None:
    _ok = cast(Callable[[Any, str], dict[str, Any]], cb._ok)
    if action == "credentials.pin":
        payload = run_pin_recovery_workflow(
            app.devices,
            serial=cb._opt(params.get("serial")) or cb._opt(params.get("selected_device_serial")),
            length=cb._int_param(cb._require(params, "length")),
            case_dir=cb._path_param(params.get("case_dir")),
            output_dir=cb._path_param(params.get("output_dir")),
            preferred_serial=app.selected_device_serial,
            target_serials=cb._csv_list(params.get("target_serials")),
            source_command="tui credentials.pin",
            export_pin_recovery=cb.export_pin_recovery,
            recover_pin=cb.recover_pin,
            write_json=cb.write_json,
            register_case_artifact=cb.register_case_artifact,
            load_case_manifest=cb.load_case_manifest,
        )
        return _ok(payload, f"Recovered PIN for {payload['serial']}")
    if action == "credentials.gesture":
        payload = run_gesture_recovery_workflow(
            app.devices,
            serial=cb._opt(params.get("serial")) or cb._opt(params.get("selected_device_serial")),
            case_dir=cb._path_param(params.get("case_dir")),
            output_dir=cb._path_param(params.get("output_dir")),
            preferred_serial=app.selected_device_serial,
            target_serials=cb._csv_list(params.get("target_serials")),
            source_command="tui credentials.gesture",
            export_gesture_recovery=cb.export_gesture_recovery,
            recover_gesture=cb.recover_gesture,
            write_json=cb.write_json,
            register_case_artifact=cb.register_case_artifact,
            load_case_manifest=cb.load_case_manifest,
        )
        return _ok(payload, f"Recovered gesture pattern for {payload['serial']}")
    if action == "credentials.wifi":
        payload = run_wifi_workflow(
            app.devices,
            serial=cb._opt(params.get("serial")) or cb._opt(params.get("selected_device_serial")),
            case_dir=cb._path_param(params.get("case_dir")),
            output_dir=cb._path_param(params.get("output_dir")),
            preferred_serial=app.selected_device_serial,
            target_serials=cb._csv_list(params.get("target_serials")),
            source_command="tui credentials.wifi",
            export_wifi_credentials=cb.export_wifi_credentials,
            extract_wifi_passwords=cb.extract_wifi_passwords,
            write_json=cb.write_json,
            register_case_artifact=cb.register_case_artifact,
            load_case_manifest=cb.load_case_manifest,
        )
        return _ok(payload, f"Collected WiFi credentials from {payload['serial']}")
    if action == "credentials.keystore":
        payload = run_keystore_workflow(
            app.devices,
            serial=cb._opt(params.get("serial")) or cb._opt(params.get("selected_device_serial")),
            case_dir=cb._path_param(params.get("case_dir")),
            output_dir=cb._path_param(params.get("output_dir")),
            preferred_serial=app.selected_device_serial,
            target_serials=cb._csv_list(params.get("target_serials")),
            source_command="tui credentials.keystore",
            inspect_keystore=cb.inspect_keystore,
            list_keystore=cb.list_keystore,
            write_json=cb.write_json,
            register_case_artifact=cb.register_case_artifact,
            load_case_manifest=cb.load_case_manifest,
        )
        return _ok(payload, f"Collected keystore inventory from {payload['serial']}")
    if action == "credentials.passkeys":
        payload = run_passkey_workflow(
            app.devices,
            serial=cb._opt(params.get("serial")) or cb._opt(params.get("selected_device_serial")),
            case_dir=cb._path_param(params.get("case_dir")),
            output_dir=cb._path_param(params.get("output_dir")),
            limit=cb._int_param(params.get("limit")) or 200,
            preferred_serial=app.selected_device_serial,
            target_serials=cb._csv_list(params.get("target_serials")),
            source_command="tui credentials.passkeys",
            pull_passkey_artifacts=cb.pull_passkey_artifacts,
            write_json=cb.write_json,
            register_case_artifact=cb.register_case_artifact,
            load_case_manifest=cb.load_case_manifest,
        )
        return _ok(
            payload,
            f"Exported {payload['artifact_count']} passkey artifacts from {payload['serial']}",
        )

    if action == "credentials.offline_pin":
        target_hash = cb._require(params, "hash")
        algo = cb._opt(params.get("algo")) or "sha256"
        length = cb._int_param(cb._require(params, "length"))
        case_dir = cb._path_param(params.get("case_dir"))
        output = cb._path_param(params.get("output"))
        import time

        started = time.time()
        pin = cb.lockknife_core.bruteforce_numeric_pin(target_hash, algo.lower(), int(length))
        elapsed = time.time() - started
        if pin is None:
            return _ok(
                {"found": False, "elapsed_s": elapsed}, f"No PIN found (elapsed={elapsed:.2f}s)"
            )
        result = {"found": True, "pin": pin, "elapsed_s": elapsed}
        if output is not None:
            cb.write_json(output, result)
            artifact_id = cb._register_case_output(
                case_dir,
                path=output,
                category="crack-pin-offline",
                source_command="credentials.offline_pin",
                metadata={"hash_prefix": target_hash[:16], "algo": algo, "length": length},
            )
            result["artifact_id"] = artifact_id
        return _ok(result, f"PIN found: {pin} (elapsed={elapsed:.2f}s)")

    if action == "credentials.offline_password":
        target_hash = cb._require(params, "hash")
        algo = cb._opt(params.get("algo")) or "sha256"
        wordlist = cb._require(params, "wordlist")
        case_dir = cb._path_param(params.get("case_dir"))
        output = cb._path_param(params.get("output"))
        found = cb.lockknife_core.dictionary_attack(target_hash, algo.lower(), wordlist)
        if found is None:
            return _ok({"found": False}, "No password found in wordlist")
        result = {"found": True, "password": found}
        if output is not None:
            cb.write_json(output, result)
            artifact_id = cb._register_case_output(
                case_dir,
                path=output,
                category="crack-password-offline",
                source_command="credentials.offline_password",
                metadata={"hash_prefix": target_hash[:16], "algo": algo},
            )
            result["artifact_id"] = artifact_id
        return _ok(result, f"Password found: {found}")

    if action == "credentials.offline_password_rules":
        target_hash = cb._require(params, "hash")
        algo = cb._opt(params.get("algo")) or "sha256"
        wordlist = cb._require(params, "wordlist")
        max_suffix = cb._int_param(params.get("max_suffix")) or 100
        case_dir = cb._path_param(params.get("case_dir"))
        output = cb._path_param(params.get("output"))
        from lockknife.modules.credentials.password import crack_password_with_rules

        found = crack_password_with_rules(
            target_hash, algo, cb._path_param(wordlist), max_suffix=max_suffix
        )
        if found is None:
            return _ok({"found": False}, "No password found with rules")
        result = {"found": True, "password": found}
        if output is not None:
            cb.write_json(output, result)
            artifact_id = cb._register_case_output(
                case_dir,
                path=output,
                category="crack-password-rules-offline",
                source_command="credentials.offline_password_rules",
                metadata={"hash_prefix": target_hash[:16], "algo": algo, "max_suffix": max_suffix},
            )
            result["artifact_id"] = artifact_id
        return _ok(result, f"Password found with rules: {found}")

    return None
