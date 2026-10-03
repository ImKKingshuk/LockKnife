mod action_capabilities;
mod action_descriptions;
mod action_help;
mod action_recovery;
mod module_metadata;

use super::{CapabilityMetadata, ModuleEntry};

pub(crate) fn default_modules() -> Vec<ModuleEntry> {
    let catalog: serde_json::Value = serde_json::from_str(include_str!(
        "../../../lockknife_headless_cli/actions/catalog.json"
    ))
    .expect("packaged action catalog must be valid JSON");
    catalog["modules"]
        .as_array()
        .expect("packaged action catalog must contain modules")
        .iter()
        .map(|value| super::config::parse_catalog_module(value).expect("invalid packaged module"))
        .collect()
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
