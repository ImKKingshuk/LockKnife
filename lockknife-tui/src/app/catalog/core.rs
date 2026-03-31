use super::super::ModuleEntry;
use super::fields::{action, module, number_field, text_field};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "core",
        "Diagnostics",
        vec![
            action("core.health", "Core health", vec![], false, false),
            action("core.doctor", "Dependency doctor", vec![], false, false),
            action("core.features", "Feature matrix", vec![], false, false),
            action("device.list", "List devices", vec![], false, false),
            action(
                "device.info",
                "Device info",
                vec![text_field("serial", "Device serial", "")],
                false,
                false,
            ),
            action(
                "device.connect",
                "Connect to device",
                vec![text_field("host", "Host:port", "127.0.0.1:5555")],
                false,
                false,
            ),
            action(
                "device.shell",
                "Execute shell command",
                vec![
                    text_field("serial", "Device serial", ""),
                    text_field("command", "Command", "echo hello"),
                    number_field("timeout", "Timeout (seconds)", "30"),
                ],
                false,
                false,
            ),
        ],
    )
}
