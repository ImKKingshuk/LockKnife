use super::*;

impl App {
    pub fn start_prompt(&mut self, state: PromptState) {
        self.overlay = Overlay::Prompt(state);
    }

    pub fn start_confirm(&mut self, state: ConfirmState) {
        self.overlay = Overlay::Confirm(state);
    }

    #[allow(dead_code)]
    pub fn clear_overlay(&mut self) {
        self.overlay = Overlay::None;
    }

    pub fn active_case_dir(&self) -> Option<&str> {
        self.active_case_dir
            .as_deref()
            .filter(|value| !value.trim().is_empty())
    }

    pub fn active_case_summary(&self, max_chars: usize) -> Option<String> {
        self.active_case_dir()
            .map(|value| summarize_path(value, max_chars.max(8)))
    }

    pub fn apply_action_prompt_context(
        &self,
        action: &ModuleAction,
        fields: &mut [PromptField],
        help_lines: &mut Vec<String>,
    ) {
        if action.is_case_aware() {
            if let Some(active_case) = self.active_case_dir() {
                if action.id != "case.init" {
                    for field in fields.iter_mut() {
                        if field.key == "case_dir" {
                            field.value = active_case.to_string();
                        }
                    }
                }
                help_lines.insert(
                    0,
                    format!(
                        "Active case in this TUI session: {}.",
                        self.active_case_summary(56)
                            .unwrap_or_else(|| active_case.to_string())
                    ),
                );
            } else {
                help_lines.insert(
                    0,
                    "No active case yet — set Case directory to route outputs into a case workspace."
                        .to_string(),
                );
            }
        }

        let preferred_device_serial = self
            .selected_device_serial()
            .or_else(|| self.latest_result_device_serial());
        if let Some(device_serial) = preferred_device_serial.as_deref() {
            prefill_prompt_field_if_empty(fields, "target_serials", device_serial);
            prefill_prompt_field_if_empty(fields, "serial", device_serial);
            prefill_prompt_field_if_empty(fields, "device_serial", device_serial);
            prefill_prompt_field_if_empty(fields, "device_serials", device_serial);
            prefill_prompt_field_if_empty(fields, "device_id", device_serial);
        }

        insert_prompt_preflight_lines(action, preferred_device_serial.as_deref(), help_lines);

        if let Some(category) = self.latest_result_artifact_category().as_deref() {
            prefill_prompt_field_if_empty(fields, "categories", category);
            prefill_prompt_field_if_matches(fields, "category", category, &["derived"]);
        }

        if let Some(source_command) = self.latest_result_source_command().as_deref() {
            prefill_prompt_field_if_empty(fields, "source_commands", source_command);
            prefill_prompt_field_if_matches(
                fields,
                "source_command",
                source_command,
                &["case register"],
            );
        }

        if action.id == "report.generate" {
            if let Some(case_dir) =
                field_value(fields, "case_dir").filter(|value| !value.is_empty())
            {
                let case_id = self
                    .latest_result_case_id()
                    .unwrap_or_else(|| derive_case_id_from_dir(case_dir));
                if matches!(
                    field_value(fields, "case_id"),
                    Some("") | Some("CASE123") | None
                ) {
                    set_prompt_field(fields, "case_id", &case_id);
                }
                if field_value(fields, "output") == Some("report.html") {
                    set_prompt_field(fields, "output", "");
                }
                help_lines.push(
                    "Case-first reporting: leave Artifacts JSON blank to summarize the active case automatically."
                        .to_string(),
                );
            }
        }

        if let Some(playbook) = action_playbook_summary(&action.id) {
            help_lines.push(playbook);
        }
        if let Some(next_step) = action_next_step_hint(&action.id) {
            help_lines.push(next_step);
        }

        self.apply_persisted_prompt_defaults(fields);
    }

    pub(crate) fn build_action_prompt(
        &self,
        module_index: usize,
        action_index: usize,
    ) -> Option<PromptState> {
        let action = self
            .modules
            .get(module_index)
            .and_then(|module| module.actions.get(action_index))?;
        let mut fields = action.fields.clone();
        let mut help_lines = action
            .help_lines()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        self.apply_action_prompt_context(action, &mut fields, &mut help_lines);
        Some(PromptState {
            title: action.label.clone(),
            description: action.description().map(str::to_string),
            help_lines,
            fields,
            index: 0,
            target: PromptTarget::Action {
                module_index,
                action_index,
            },
        })
    }

    pub(crate) fn build_action_prompt_by_id(&self, action_id: &str) -> Option<PromptState> {
        let (module_index, action_index) = self.find_action_indices(action_id)?;
        self.build_action_prompt(module_index, action_index)
    }

    pub(crate) fn build_main_case_prompt(
        &self,
        action_id: &str,
    ) -> Result<PromptState, &'static str> {
        let mut prompt = self
            .build_action_prompt_by_id(action_id)
            .ok_or("Requested case shortcut is unavailable")?;
        match action_id {
            "case.summary" => {
                let line = match self.active_case_dir() {
                    Some(active_case) => format!(
                        "Quick case access from the main TUI · edit Case directory to switch from {}.",
                        active_case
                    ),
                    None => "Quick case access from the main TUI · set Case directory to open or resume a workspace."
                        .to_string(),
                };
                prompt.help_lines.insert(0, line);
            }
            "case.init" => {
                let line = match self.active_case_dir() {
                    Some(active_case) => format!(
                        "Quick case init from the main TUI · current active case stays {} until a new workspace succeeds.",
                        active_case
                    ),
                    None => {
                        "Quick case init from the main TUI · create and seed a new case workspace."
                            .to_string()
                    }
                };
                prompt.help_lines.insert(0, line);
            }
            _ => {}
        }
        Ok(prompt)
    }

    pub(crate) fn build_case_dashboard_prompt(
        &self,
        action_id: &str,
    ) -> Result<PromptState, &'static str> {
        let mut prompt = match action_id {
            "case.artifacts"
                if !artifact_filter_history_is_empty(&self.artifact_filter_history) =>
            {
                self.build_recent_artifact_filter_prompt().or_else(|_| {
                    self.build_action_prompt_by_id(action_id)
                        .ok_or("Requested case action is unavailable")
                })?
            }
            _ => self
                .build_action_prompt_by_id(action_id)
                .ok_or("Requested case action is unavailable")?,
        };

        let context_line = match action_id {
            "case.summary" => match self.active_case_dir() {
                Some(active_case) => format!(
                    "Case dashboard quick action · summary stays scoped to {}.",
                    active_case
                ),
                None => "Case dashboard quick action · set Case directory to inspect an existing workspace."
                    .to_string(),
            },
            "case.graph" => match self.active_case_dir() {
                Some(active_case) => format!(
                    "Case dashboard quick action · lineage graph starts from {}.",
                    active_case
                ),
                None => "Case dashboard quick action · set Case directory to inspect lineage across a workspace."
                    .to_string(),
            },
            "case.artifacts" => {
                "Case dashboard quick action · artifact inventory opens with active-case routing and any saved filter recall."
                    .to_string()
            }
            "case.export" => {
                "Case dashboard quick action · export a filtered or full case bundle from the active workspace."
                    .to_string()
            }
            "case.enrich" => {
                "Case dashboard quick action · bundle network, intelligence, and AI enrichment across matching case artifacts."
                    .to_string()
            }
            "case.jobs" => {
                "Case dashboard quick action · inspect persisted job history for the active workspace."
                    .to_string()
            }
            "case.job" => {
                "Case dashboard quick action · inspect one persisted job in detail, including recent log lines."
                    .to_string()
            }
            "case.resume_job" => {
                "Case dashboard quick action · resume the latest resumable job from its saved parameters."
                    .to_string()
            }
            "case.retry_job" => {
                "Case dashboard quick action · retry a finished job from its saved parameters."
                    .to_string()
            }
            "report.generate" => {
                "Case dashboard quick action · generate a report directly from the active case workspace."
                    .to_string()
            }
            "report.chain_of_custody" => {
                "Case dashboard quick action · derive a reviewer-ready chain-of-custody ledger from the active case workspace."
                    .to_string()
            }
            "report.integrity" => {
                "Case dashboard quick action · verify registered artifact hashes and export an integrity summary."
                    .to_string()
            }
            _ => "Case dashboard quick action.".to_string(),
        };
        if let Some(active_case) = self.active_case_dir() {
            if fields_have_key(&prompt.fields, "case_dir") {
                set_prompt_field(&mut prompt.fields, "case_dir", active_case);
            }
        }
        match action_id {
            "case.job" => {
                if let Some(job_id) = self.latest_case_job_id() {
                    set_prompt_field(&mut prompt.fields, "job_id", &job_id);
                }
            }
            "case.resume_job" => {
                if let Some(job_id) =
                    self.latest_case_job_id_by_status(&["failed", "partial", "cancelled"])
                {
                    set_prompt_field(&mut prompt.fields, "job_id", &job_id);
                }
            }
            "case.retry_job" => {
                if let Some(job_id) = self.latest_case_job_id_by_status(&[
                    "failed",
                    "partial",
                    "cancelled",
                    "succeeded",
                ]) {
                    set_prompt_field(&mut prompt.fields, "job_id", &job_id);
                }
            }
            "report.generate" | "report.chain_of_custody" | "report.integrity" => {
                if let Some(case_dir) = self.active_case_dir() {
                    let case_id = derive_case_id_from_dir(case_dir);
                    if fields_have_key(&prompt.fields, "case_id") {
                        set_prompt_field(&mut prompt.fields, "case_id", &case_id);
                    }
                }
            }
            _ => {}
        }
        prompt.help_lines.insert(0, context_line);
        Ok(prompt)
    }

    pub(crate) fn open_diagnostics_menu(&mut self) -> bool {
        let Some((module_index, action_index)) = self.find_action_indices("core.doctor") else {
            return false;
        };

        self.selected_module = module_index;
        self.active_panel = Panel::Modules;
        self.overlay = Overlay::ActionMenu(ActionMenuState {
            module_index,
            action_index,
        });
        true
    }

    pub(crate) fn build_recent_case_prompt(&self) -> Result<PromptState, &'static str> {
        let recent_cases = self.recent_case_options();
        if recent_cases.is_empty() {
            return Err("No recent cases in this TUI session yet");
        }

        let mut prompt = self
            .build_action_prompt_by_id("case.summary")
            .ok_or("Requested case shortcut is unavailable")?;
        if let Some(field) = prompt
            .fields
            .iter_mut()
            .find(|field| field.key == "case_dir")
        {
            field.kind = FieldKind::Choice;
            field.options = recent_cases.clone();
            field.value = recent_cases[0].clone();
        }
        prompt.help_lines.insert(
            0,
            "Recent case recall from the main TUI · use ←/→ on Case directory to reopen a recent workspace."
                .to_string(),
        );
        Ok(prompt)
    }

    pub(crate) fn build_recent_artifact_filter_prompt(&self) -> Result<PromptState, &'static str> {
        if artifact_filter_history_is_empty(&self.artifact_filter_history) {
            return Err("No recent artifact filters saved yet");
        }

        let mut prompt = self
            .build_action_prompt_by_id("case.artifacts")
            .ok_or("Requested case shortcut is unavailable")?;
        let mut recall_fields = 0usize;
        for field in prompt.fields.iter_mut() {
            let options = match field.key.as_str() {
                "query" => {
                    history_choice_options(&field.value, &self.artifact_filter_history.queries)
                }
                "path_contains" => history_choice_options(
                    &field.value,
                    &self.artifact_filter_history.path_contains,
                ),
                "metadata_contains" => history_choice_options(
                    &field.value,
                    &self.artifact_filter_history.metadata_contains,
                ),
                "categories" => {
                    history_choice_options(&field.value, &self.artifact_filter_history.categories)
                }
                "exclude_categories" => history_choice_options(
                    &field.value,
                    &self.artifact_filter_history.exclude_categories,
                ),
                "source_commands" => history_choice_options(
                    &field.value,
                    &self.artifact_filter_history.source_commands,
                ),
                "device_serials" => history_choice_options(
                    &field.value,
                    &self.artifact_filter_history.device_serials,
                ),
                _ => Vec::new(),
            };
            if options.is_empty() {
                continue;
            }
            field.kind = FieldKind::Choice;
            field.options = options.clone();
            field.value = options[0].clone();
            recall_fields += 1;
        }

        if let Some(limit) = self.artifact_filter_history.limits.first() {
            if let Some(field) = prompt.fields.iter_mut().find(|field| field.key == "limit") {
                field.value = limit.clone();
                recall_fields += 1;
            }
        }

        if recall_fields == 0 {
            return Err("No recent artifact filters saved yet");
        }

        prompt.help_lines.insert(
            0,
            "Artifact recall from the main TUI · use ←/→ on filter fields to reuse recent artifact-search values."
                .to_string(),
        );
        Ok(prompt)
    }

    pub fn apply_search_query(&mut self, target: SearchTarget, query: String) {
        let trimmed = query.trim().to_string();
        let target_label = target.summary_label();
        match target {
            SearchTarget::Modules => {
                self.search = if trimmed.is_empty() {
                    None
                } else {
                    Some(SearchState {
                        target: SearchTarget::Modules,
                        query: trimmed.clone(),
                    })
                };
                self.module_scroll = 0;
            }
            SearchTarget::Output => {
                self.search = if trimmed.is_empty() {
                    None
                } else {
                    Some(SearchState {
                        target: SearchTarget::Output,
                        query: trimmed.clone(),
                    })
                };
                self.output_scroll = 0;
            }
        }

        let message = if trimmed.is_empty() {
            format!("Cleared {} filter", target_label)
        } else {
            format!(
                "Filtering {} by {}",
                target_label,
                summarize_feedback_query(&trimmed, 24)
            )
        };
        self.push_feedback("info", message);
    }

    pub(crate) fn find_action_indices(&self, action_id: &str) -> Option<(usize, usize)> {
        self.modules
            .iter()
            .enumerate()
            .find_map(|(module_index, module)| {
                module
                    .actions
                    .iter()
                    .position(|action| action.id == action_id)
                    .map(|action_index| (module_index, action_index))
            })
    }

    pub(crate) fn action_failure_recovery_hint(&self, action_id: &str) -> Option<&'static str> {
        let (module_index, action_index) = self.find_action_indices(action_id)?;
        let module = self.modules.get(module_index)?;
        let action = module.actions.get(action_index)?;
        action.recovery_hint().or_else(|| module.recovery_hint())
    }

    pub(crate) fn recent_case_options(&self) -> Vec<String> {
        let mut cases = Vec::new();
        if let Some(active_case) = self.active_case_dir() {
            cases.push(active_case.to_string());
        }
        for case_dir in &self.recent_case_dirs {
            if !cases.iter().any(|existing| existing == case_dir) {
                cases.push(case_dir.clone());
            }
        }
        cases
    }
}
