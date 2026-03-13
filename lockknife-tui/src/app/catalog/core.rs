use super::super::ModuleEntry;
use super::fields::{action, module};

pub(super) fn build_module() -> ModuleEntry {
    module(
        "core",
        "Diagnostics",
        vec![
            action("core.health", "Core health", vec![], false, false),
            action("core.doctor", "Dependency doctor", vec![], false, false),
            action("core.features", "Feature matrix", vec![], false, false),
        ],
    )
}
