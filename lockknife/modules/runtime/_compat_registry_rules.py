from __future__ import annotations

from lockknife.modules.runtime._compat_registry_models import RuntimeCompatibilityRule

RUNTIME_COMPATIBILITY_RULES: tuple[RuntimeCompatibilityRule, ...] = (
    RuntimeCompatibilityRule(
        rule_id="spawn-restarts-app",
        title="Spawn mode relaunches the app",
        severity="warn",
        condition="spawn_restarts_app",
        message=(
            "Spawn mode restarts the target app before instrumentation, which can clear ephemeral "
            "in-app state before hooks land."
        ),
        recovery_hint=(
            "Use attach mode if you need the already-running process state and the target app is "
            "currently visible."
        ),
        recommended_next=(
            "Start the managed session when you are ready for a relaunch, or switch to attach mode "
            "if preserving state matters more."
        ),
        attach_modes=("spawn",),
        tags=("state", "startup"),
    ),
    RuntimeCompatibilityRule(
        rule_id="attach-needs-running-process",
        title="Attach mode needs a live process",
        severity="fail",
        condition="attach_requires_running_process",
        message="Attach mode cannot succeed until the target process is already running on the device.",
        recovery_hint="Launch the target app first or switch to spawn mode before retrying.",
        recommended_next="Open the app on the device and rerun attach-mode preflight before reconnecting.",
        attach_modes=("attach",),
        tags=("attach", "process"),
    ),
    RuntimeCompatibilityRule(
        rule_id="trace-high-volume",
        title="Trace sessions generate high event volume",
        severity="warn",
        condition="trace_high_volume",
        message=(
            "Trace sessions can emit high-volume events and grow runtime logs quickly, especially "
            "when the class or method scope is broad."
        ),
        recovery_hint="Narrow the traced class/method or shorten the capture window for the first run.",
        recommended_next="Prefer a targeted trace first, then widen only after the first event review.",
        session_kinds=("trace",),
        tags=("trace", "volume"),
    ),
    RuntimeCompatibilityRule(
        rule_id="visibility-unconfirmed",
        title="App visibility is not confirmed yet",
        severity="warn",
        condition="visibility_unconfirmed",
        message=(
            "The runtime target could not be confirmed through Frida application listing, so attach "
            "or reconnect flows may still need manual verification."
        ),
        recovery_hint="Confirm the package name or fall back to spawn mode if attach readiness remains uncertain.",
        recommended_next="Use a spawn-mode launch first if the attach target is still ambiguous.",
        tags=("visibility", "discovery"),
    ),
    RuntimeCompatibilityRule(
        rule_id="ssl-attach-misses-early-hooks",
        title="Attach mode can miss early TLS hooks",
        severity="warn",
        condition="ssl_attach_fragile",
        message=(
            "SSL bypass in attach mode can miss startup-time certificate pinning paths that execute "
            "before the script loads."
        ),
        recovery_hint="Prefer spawn mode when you need the bypass script loaded before network initialization.",
        recommended_next="Rerun the SSL bypass session in spawn mode if early pinning checks are still active.",
        attach_modes=("attach",),
        session_kinds=("bypass_ssl",),
        tags=("tls", "startup"),
    ),
    RuntimeCompatibilityRule(
        rule_id="root-attach-misses-startup-checks",
        title="Attach mode can miss startup root checks",
        severity="warn",
        condition="root_attach_fragile",
        message=(
            "Root-bypass sessions attached after launch can miss root-detection checks that only run "
            "during startup."
        ),
        recovery_hint="Use spawn mode when the target performs its root checks during process initialization.",
        recommended_next="Switch to spawn mode if the app still trips root detection after attach.",
        attach_modes=("attach",),
        session_kinds=("bypass_root",),
        tags=("root", "startup"),
    ),
)
