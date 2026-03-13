pub(super) fn action_recovery_hint(action_id: &str) -> Option<&'static str> {
    match action_id {
        "report.generate" => Some(
            "Recovery: HTML/JSON/CSV work now; install WeasyPrint or xhtml2pdf when PDF output is required.",
        ),
        "report.integrity" => Some(
            "Recovery: run Case summary first and make sure the workspace still contains the registered artifacts you want to verify.",
        ),
        "network.capture" => Some(
            "Recovery: run Diagnostics → Dependency doctor, install `lockknife[network]`, and verify root + tcpdump on the device.",
        ),
        "network.summarize" | "network.api_discovery" => Some(
            "Recovery: open Diagnostics → Dependency doctor, then `uv sync --extra network` to unlock PCAP analysis workflows.",
        ),
        "apk.permissions" | "apk.analyze" | "apk.decompile" | "apk.vulnerability" => Some(
            "Recovery: open Diagnostics → Dependency doctor, then `uv sync --extra apk`; install apktool/jadx as well when you want richer decompile output.",
        ),
        "runtime.hook"
        | "runtime.bypass_ssl"
        | "runtime.bypass_root"
        | "runtime.trace"
        | "runtime.preflight"
        | "runtime.sessions"
        | "runtime.session"
        | "runtime.session_reload"
        | "runtime.session_reconnect"
        | "runtime.session_stop"
        | "runtime.memory_search"
        | "runtime.heap_dump" => Some(
            "Recovery: open Diagnostics → Dependency doctor, then `uv sync --extra frida` and verify the target Frida server.",
        ),
        "intelligence.virustotal" | "intelligence.otx" => Some(
            "Recovery: open Diagnostics → Dependency doctor, install `uv sync --extra threat-intel`, and set the required API keys.",
        ),
        "ai.anomaly_score" | "ai.predict_passwords" => Some(
            "Recovery: open Diagnostics → Dependency doctor, then `uv sync --extra ml` to enable the optional AI helpers.",
        ),
        _ => None,
    }
}
