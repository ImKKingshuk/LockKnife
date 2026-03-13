use super::super::{ModuleAction, ModuleEntry};
use super::fields::{
    action, bool_field, case_dir_field, choice_field, module, number_field, text_field,
};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "runtime",
        "Runtime",
        vec![
            hook_action(),
            builtin_script_action(),
            bypass_ssl_action(),
            bypass_root_action(),
            trace_action(),
            preflight_action(),
            sessions_action(),
            session_detail_action(),
            session_reload_action(),
            session_reconnect_action(),
            session_stop_action(),
            memory_search_action(),
            heap_dump_action(),
        ],
    )
}

fn hook_action() -> ModuleAction {
    action(
        "runtime.hook",
        "Start hook session",
        vec![
            text_field("app_id", "App ID", ""),
            text_field("session_name", "Session name", "hook-session"),
            text_field("script", "Script path", ""),
            text_field("device_id", "Device ID", ""),
            choice_field("attach_mode", "Attach mode", "spawn", &["spawn", "attach"]),
            number_field("timeout", "Initial wait seconds", "1"),
            text_field("output", "Session summary output path (optional)", ""),
            case_dir_field(),
        ],
        false,
        true,
    )
}

fn bypass_ssl_action() -> ModuleAction {
    action(
        "runtime.bypass_ssl",
        "Start SSL bypass session",
        vec![
            text_field("app_id", "App ID", ""),
            text_field("session_name", "Session name", "ssl-bypass"),
            text_field("device_id", "Device ID", ""),
            choice_field("attach_mode", "Attach mode", "spawn", &["spawn", "attach"]),
            number_field("timeout", "Initial wait seconds", "1"),
            text_field("output", "Session summary output path (optional)", ""),
            case_dir_field(),
        ],
        false,
        true,
    )
}

fn builtin_script_action() -> ModuleAction {
    action(
        "runtime.load_builtin_script",
        "Load built-in script",
        vec![
            text_field("app_id", "App ID", ""),
            text_field("session_name", "Session name", "builtin-script"),
            choice_field(
                "builtin_script",
                "Built-in script",
                "ssl_bypass",
                &[
                    "ssl_bypass",
                    "root_bypass",
                    "debug_bypass",
                    "crypto_intercept",
                ],
            ),
            text_field("device_id", "Device ID", ""),
            choice_field("attach_mode", "Attach mode", "spawn", &["spawn", "attach"]),
            number_field("timeout", "Initial wait seconds", "1"),
            text_field("output", "Session summary output path (optional)", ""),
            case_dir_field(),
        ],
        false,
        true,
    )
}

fn bypass_root_action() -> ModuleAction {
    action(
        "runtime.bypass_root",
        "Start root bypass session",
        vec![
            text_field("app_id", "App ID", ""),
            text_field("session_name", "Session name", "root-bypass"),
            text_field("device_id", "Device ID", ""),
            choice_field("attach_mode", "Attach mode", "spawn", &["spawn", "attach"]),
            number_field("timeout", "Initial wait seconds", "1"),
            text_field("output", "Session summary output path (optional)", ""),
            case_dir_field(),
        ],
        false,
        true,
    )
}

fn trace_action() -> ModuleAction {
    action(
        "runtime.trace",
        "Start trace session",
        vec![
            text_field("app_id", "App ID", ""),
            text_field("session_name", "Session name", "trace-session"),
            text_field("class", "Class", ""),
            text_field("method", "Method", ""),
            text_field("device_id", "Device ID", ""),
            choice_field("attach_mode", "Attach mode", "spawn", &["spawn", "attach"]),
            number_field("timeout", "Initial wait seconds", "1"),
            text_field("output", "Session summary output path (optional)", ""),
            case_dir_field(),
        ],
        false,
        true,
    )
}

fn preflight_action() -> ModuleAction {
    action(
        "runtime.preflight",
        "Preflight",
        vec![
            text_field("app_id", "App ID", ""),
            text_field("device_id", "Device ID", ""),
            choice_field("attach_mode", "Attach mode", "spawn", &["spawn", "attach"]),
            text_field("session_kind", "Session kind (optional)", ""),
        ],
        false,
        false,
    )
}

fn sessions_action() -> ModuleAction {
    action(
        "runtime.sessions",
        "Session inventory",
        vec![
            case_dir_field(),
            text_field("statuses", "Statuses (csv)", ""),
            text_field("session_kinds", "Kinds (csv)", ""),
            text_field("attach_modes", "Attach modes (csv)", ""),
            text_field("query", "Query", ""),
            number_field("limit", "Limit", "20"),
        ],
        false,
        false,
    )
}

fn session_detail_action() -> ModuleAction {
    action(
        "runtime.session",
        "Session detail",
        vec![
            case_dir_field(),
            text_field("session_id", "Session ID", ""),
            text_field("event_cursor", "Event cursor (optional)", ""),
            number_field("event_limit", "Event limit", "100"),
        ],
        false,
        false,
    )
}

fn session_reload_action() -> ModuleAction {
    action(
        "runtime.session_reload",
        "Reload session script",
        vec![
            case_dir_field(),
            text_field("session_id", "Session ID", ""),
            text_field("script", "New script path (optional)", ""),
            text_field("builtin_script", "Built-in script name (optional)", ""),
            text_field("script_label", "Script label (optional)", ""),
            number_field("timeout", "Post-reload wait seconds", "0.5"),
        ],
        false,
        true,
    )
}

fn session_reconnect_action() -> ModuleAction {
    action(
        "runtime.session_reconnect",
        "Reconnect session",
        vec![
            case_dir_field(),
            text_field("session_id", "Session ID", ""),
            text_field("attach_mode", "Attach mode override (optional)", ""),
            number_field("timeout", "Post-reconnect wait seconds", "0.5"),
        ],
        false,
        true,
    )
}

fn session_stop_action() -> ModuleAction {
    action(
        "runtime.session_stop",
        "Stop session",
        vec![case_dir_field(), text_field("session_id", "Session ID", "")],
        false,
        true,
    )
}

fn memory_search_action() -> ModuleAction {
    action(
        "runtime.memory_search",
        "Memory search",
        vec![
            text_field("app_id", "App ID", ""),
            text_field("pattern", "Pattern", ""),
            bool_field("hex", "Hex pattern", false),
            text_field("protection", "Protection", "r--"),
            number_field("timeout", "Timeout (s)", "30"),
            text_field("device_id", "Device ID", ""),
            text_field("output", "Result output path (optional)", ""),
            case_dir_field(),
        ],
        false,
        true,
    )
}

fn heap_dump_action() -> ModuleAction {
    action(
        "runtime.heap_dump",
        "Heap dump",
        vec![
            text_field("app_id", "App ID", ""),
            text_field("output", "Remote output path", "/sdcard/lockknife.hprof"),
            number_field("timeout", "Timeout (s)", "30"),
            text_field("device_id", "Device ID", ""),
            text_field("result_output", "Result output path (optional)", ""),
            case_dir_field(),
        ],
        false,
        true,
    )
}
