use crate::app::ModuleAction;

pub(in crate::ui) fn status_badge(status: &str) -> &'static str {
    match status {
        "production-ready" => "ready",
        "functional" => "func",
        "best-effort" => "best",
        "experimental" => "exp",
        "dependency-gated" => "gated",
        "mixed" => "mixed",
        _ => "info",
    }
}

pub(in crate::ui) fn summarize_case_path(value: &str, max_chars: usize) -> String {
    let trimmed = value.trim();
    let mut chars = trimmed.chars();
    let shortened = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{}…", shortened)
    } else {
        shortened
    }
}

pub(in crate::ui) fn looks_like_path(value: &str) -> bool {
    value.contains('/') || value.contains('\\')
}

pub(in crate::ui) fn summarize_query(query: &str, max_chars: usize) -> String {
    let trimmed = query.trim();
    let mut chars = trimmed.chars();
    let shortened = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("\"{}…\"", shortened)
    } else {
        format!("\"{}\"", shortened)
    }
}

pub(in crate::ui) fn summarize_plain_text(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let trimmed = text.trim();
    let mut chars = trimmed.chars();
    let shortened = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{}…", shortened)
    } else {
        shortened
    }
}

pub(in crate::ui) fn dialog_title(title: &str, width: u16, suffix: Option<&str>) -> String {
    if width < 24 {
        return summarize_plain_text(title, usize::from(width.saturating_sub(4).max(8)));
    }

    match suffix {
        Some(suffix) if width >= 36 => format!("{} ({})", title, suffix),
        _ => summarize_plain_text(title, usize::from(width.saturating_sub(4).max(8))),
    }
}

pub(in crate::ui) fn action_preflight_summary(action: &ModuleAction) -> Option<String> {
    let metadata = action.capability_metadata()?;
    if !action_needs_preflight(action) {
        return None;
    }

    Some(format!(
        "Preflight: {} [{}] · requires {}.",
        metadata.status,
        status_badge(metadata.status),
        metadata.requirements
    ))
}

pub(in crate::ui) fn action_needs_preflight(action: &ModuleAction) -> bool {
    action.capability_metadata().is_some_and(|metadata| {
        matches!(
            metadata.status,
            "dependency-gated" | "best-effort" | "experimental"
        )
    })
}
