mod action_capabilities;
mod action_descriptions;
mod action_help;
mod action_recovery;
mod ai;
mod analyze;
mod apk;
mod case;
mod core;
mod credentials;
mod crypto;
mod exploitation;
mod extraction;
mod fields;
mod forensics;
mod intelligence;
mod module_metadata;
mod network;
mod plugins;
mod runtime;
mod security;

use super::{CapabilityMetadata, ModuleEntry, PromptField};

pub(crate) fn default_modules() -> Vec<ModuleEntry> {
    vec![
        credentials::build_module(),
        extraction::build_module(),
        forensics::build_module(),
        network::build_module(),
        apk::build_module(),
        runtime::build_module(),
        security::build_module(),
        intelligence::build_module(),
        case::build_module(),
        core::build_module(),
        ai::build_module(),
        crypto::build_module(),
        analyze::build_module(),
        plugins::build_module(),
        exploitation::build_module(),
    ]
}

pub(super) fn module_description(module_id: &str) -> Option<&'static str> {
    module_metadata::module_description(module_id)
}

pub(super) fn action_description(action_id: &str) -> Option<&'static str> {
    action_descriptions::action_description(action_id)
}

pub(super) fn module_help_lines(module_id: &str) -> Vec<&'static str> {
    module_metadata::module_help_lines(module_id)
}

pub(super) fn action_help_lines(action_id: &str) -> Vec<&'static str> {
    action_help::action_help_lines(action_id)
}

pub(super) fn module_capability_metadata(module_id: &str) -> Option<CapabilityMetadata> {
    module_metadata::module_capability_metadata(module_id)
}

pub(super) fn action_capability_metadata(action_id: &str) -> Option<CapabilityMetadata> {
    action_capabilities::action_capability_metadata(action_id)
}

pub(super) fn module_recovery_hint(module_id: &str) -> Option<&'static str> {
    module_metadata::module_recovery_hint(module_id)
}

pub(super) fn action_recovery_hint(action_id: &str) -> Option<&'static str> {
    action_recovery::action_recovery_hint(action_id)
}

#[allow(dead_code)]
pub(super) fn case_dir_field() -> PromptField {
    fields::case_dir_field()
}
