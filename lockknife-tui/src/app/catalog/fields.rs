use super::super::{FieldKind, ModuleAction, ModuleEntry, PromptField};

pub(in crate::app::catalog) fn module(
    id: &str,
    label: &str,
    actions: Vec<ModuleAction>,
) -> ModuleEntry {
    ModuleEntry {
        id: id.to_string(),
        label: label.to_string(),
        actions,
    }
}

pub(in crate::app::catalog) fn action(
    id: &str,
    label: &str,
    fields: Vec<PromptField>,
    requires_device: bool,
    confirm: bool,
) -> ModuleAction {
    ModuleAction {
        id: id.to_string(),
        label: label.to_string(),
        fields,
        requires_device,
        confirm,
    }
}

pub(in crate::app::catalog) fn text_field(key: &str, label: &str, value: &str) -> PromptField {
    field(key, label, value, FieldKind::Text, &[])
}

pub(in crate::app::catalog) fn number_field(key: &str, label: &str, value: &str) -> PromptField {
    field(key, label, value, FieldKind::Number, &[])
}

pub(in crate::app::catalog) fn bool_field(key: &str, label: &str, value: bool) -> PromptField {
    field(
        key,
        label,
        if value { "true" } else { "false" },
        FieldKind::Bool,
        &[],
    )
}

pub(in crate::app::catalog) fn choice_field(
    key: &str,
    label: &str,
    value: &str,
    options: &[&str],
) -> PromptField {
    field(key, label, value, FieldKind::Choice, options)
}

pub(in crate::app::catalog) fn case_dir_field() -> PromptField {
    text_field("case_dir", "Case directory", "./cases/CASE-001")
}

fn field(key: &str, label: &str, value: &str, kind: FieldKind, options: &[&str]) -> PromptField {
    PromptField {
        key: key.to_string(),
        label: label.to_string(),
        value: value.to_string(),
        kind,
        options: options.iter().map(|option| (*option).to_string()).collect(),
    }
}
