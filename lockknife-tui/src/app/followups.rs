use super::*;

impl App {
    pub(crate) fn build_result_followup_prompt(
        &self,
        action_id: &str,
    ) -> Result<PromptState, &'static str> {
        let (module_index, action_index) = self
            .find_action_indices(action_id)
            .ok_or("Requested follow-up action is unavailable")?;
        let mut prompt = self
            .build_action_prompt(module_index, action_index)
            .ok_or("Requested follow-up action is unavailable")?;
        self.apply_result_followup_context(action_id, &mut prompt.fields, &mut prompt.help_lines)?;
        Ok(prompt)
    }

    fn apply_result_followup_context(
        &self,
        action_id: &str,
        fields: &mut [PromptField],
        help_lines: &mut Vec<String>,
    ) -> Result<(), &'static str> {
        let result_case_dir = self
            .last_result_case_dir()
            .or_else(|| self.active_case_dir().map(str::to_string));

        match action_id {
            "case.summary" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                set_prompt_field(fields, "case_dir", &case_dir);
                help_lines.insert(
                    0,
                    format!("Opened from Result view for case summary on {}.", case_dir),
                );
                Ok(())
            }
            "case.artifacts" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };

                let path_hint = self.latest_result_search_path_hint();
                let category = self.latest_result_artifact_category();
                let source_command = self.latest_result_source_command();
                let device_serial = self.latest_result_device_serial();

                set_prompt_field(fields, "case_dir", &case_dir);
                if let Some(path_hint) = path_hint.as_deref() {
                    set_prompt_field(fields, "path_contains", path_hint);
                }
                if let Some(category) = category.as_deref() {
                    set_prompt_field(fields, "categories", category);
                }
                if let Some(source_command) = source_command.as_deref() {
                    set_prompt_field(fields, "source_commands", source_command);
                }
                if let Some(device_serial) = device_serial.as_deref() {
                    set_prompt_field(fields, "device_serials", device_serial);
                }
                if path_hint.is_none()
                    && category.is_none()
                    && source_command.is_none()
                    && device_serial.is_none()
                {
                    if let Some(artifact_id) = self.latest_result_artifact_id() {
                        set_prompt_field(fields, "query", &artifact_id);
                    }
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view with latest artifact-search context for {}.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "case.artifact" | "case.lineage" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                let artifact_id = self.latest_result_artifact_id();
                let artifact_path = self.latest_result_artifact_path();
                if artifact_id.is_none() && artifact_path.is_none() {
                    return Err(
                        "Latest result does not expose an artifact ID or artifact path yet",
                    );
                }

                set_prompt_field(fields, "case_dir", &case_dir);
                if let Some(artifact_id) = artifact_id.as_deref() {
                    set_prompt_field(fields, "artifact_id", artifact_id);
                }
                if let Some(path) = artifact_path.as_deref() {
                    set_prompt_field(fields, "path", path);
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view with latest artifact context for {}.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "case.register" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                let Some(path) = self.latest_result_register_path() else {
                    return Err("Latest result does not expose a registerable artifact path yet");
                };

                set_prompt_field(fields, "case_dir", &case_dir);
                set_prompt_field(fields, "path", &path);
                if let Some(category) = self.latest_result_artifact_category() {
                    set_prompt_field(fields, "category", &category);
                }
                if let Some(source_command) = self.latest_result_source_command() {
                    set_prompt_field(fields, "source_command", &source_command);
                }
                if let Some(device_serial) = self.latest_result_device_serial() {
                    set_prompt_field(fields, "device_serial", &device_serial);
                }
                if let Some(input_paths) = self.latest_result_input_paths_csv() {
                    set_prompt_field(fields, "input_paths", &input_paths);
                }
                if let Some(parent_artifact_ids) = self.latest_result_parent_artifact_ids_csv() {
                    set_prompt_field(fields, "parent_artifact_ids", &parent_artifact_ids);
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view with latest registration context for {}.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "case.jobs" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                set_prompt_field(fields, "case_dir", &case_dir);
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to inspect persisted jobs for {}.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "case.job" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                set_prompt_field(fields, "case_dir", &case_dir);
                if let Some(job_id) = self.latest_case_job_id() {
                    set_prompt_field(fields, "job_id", &job_id);
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view with the latest persisted job context for {}.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "case.resume_job" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                set_prompt_field(fields, "case_dir", &case_dir);
                if let Some(job_id) =
                    self.latest_case_job_id_by_status(&["failed", "partial", "cancelled"])
                {
                    set_prompt_field(fields, "job_id", &job_id);
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to resume the latest resumable job for {}.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "case.retry_job" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                set_prompt_field(fields, "case_dir", &case_dir);
                if let Some(job_id) = self.latest_case_job_id_by_status(&[
                    "failed",
                    "partial",
                    "cancelled",
                    "succeeded",
                ]) {
                    set_prompt_field(fields, "job_id", &job_id);
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to retry the latest finished job for {}.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "case.export" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                set_prompt_field(fields, "case_dir", &case_dir);
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to export the case workspace for {}.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "case.enrich" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                set_prompt_field(fields, "case_dir", &case_dir);
                if let Some(artifact_id) = self.latest_result_artifact_id() {
                    set_prompt_field(fields, "artifact_id", &artifact_id);
                }
                if let Some(category) = self.latest_result_artifact_category() {
                    set_prompt_field(fields, "categories", &category);
                }
                if let Some(device_serial) = self.latest_result_device_serial() {
                    set_prompt_field(fields, "device_serials", &device_serial);
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to build a case enrichment bundle for {}.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "runtime.sessions" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                set_prompt_field(fields, "case_dir", &case_dir);
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to inspect managed runtime sessions for {}.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "runtime.preflight" => {
                let Some(package) = self.latest_result_apk_package() else {
                    return Err("Latest result does not expose an APK package name yet");
                };
                set_prompt_field(fields, "app_id", &package);
                if let Some(case_dir) = result_case_dir {
                    set_prompt_field(fields, "case_dir", &case_dir);
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to preflight runtime access for APK package {}.",
                        package
                    ),
                );
                Ok(())
            }
            "runtime.bypass_ssl" | "runtime.trace" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                let Some(package) = self.latest_result_apk_package() else {
                    return Err("Latest result does not expose an APK package name yet");
                };
                set_prompt_field(fields, "case_dir", &case_dir);
                set_prompt_field(fields, "app_id", &package);
                let label = if action_id == "runtime.bypass_ssl" {
                    "start an SSL bypass session"
                } else {
                    "start a trace session"
                };
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to {} for APK package {} in {}.",
                        label, package, case_dir
                    ),
                );
                Ok(())
            }
            "runtime.session"
            | "runtime.session_reload"
            | "runtime.session_reconnect"
            | "runtime.session_stop" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                let Some(session_id) = self.latest_runtime_session_id() else {
                    return Err("Latest result does not expose a runtime session ID yet");
                };
                set_prompt_field(fields, "case_dir", &case_dir);
                set_prompt_field(fields, "session_id", &session_id);
                let label = match action_id {
                    "runtime.session" => "inspect",
                    "runtime.session_reload" => "hot-reload",
                    "runtime.session_reconnect" => "reconnect",
                    "runtime.session_stop" => "stop",
                    _ => "manage",
                };
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to {} managed runtime session {} in {}.",
                        label, session_id, case_dir
                    ),
                );
                Ok(())
            }
            "intelligence.cve" => {
                let Some(package) = self.latest_result_apk_package() else {
                    return Err("Latest result does not expose an APK package name yet");
                };
                set_prompt_field(fields, "package", &package);
                if let Some(case_dir) = result_case_dir {
                    set_prompt_field(fields, "case_dir", &case_dir);
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to correlate CVEs for APK package {}.",
                        package
                    ),
                );
                Ok(())
            }
            "security.attack_surface" => {
                let package = self.latest_result_apk_package();
                let register_path = self.latest_result_register_path();
                if package.is_none() && register_path.is_none() {
                    return Err(
                        "Latest result does not expose an APK package name or JSON artifact path yet",
                    );
                }
                if let Some(package) = package.as_deref() {
                    set_prompt_field(fields, "package", package);
                }
                if let Some(register_path) = register_path.as_deref() {
                    set_prompt_field(fields, "artifacts", register_path);
                }
                if let Some(case_dir) = result_case_dir {
                    set_prompt_field(fields, "case_dir", &case_dir);
                }
                let scope = match (package.as_deref(), register_path.as_deref()) {
                    (Some(package), Some(path)) => {
                        format!("assess APK package {} using {}", package, path)
                    }
                    (Some(package), None) => format!("assess APK package {}", package),
                    (None, Some(path)) => format!("assess attack-surface evidence from {}", path),
                    (None, None) => "assess attack surface".to_string(),
                };
                help_lines.insert(0, format!("Opened from Result view to {}.", scope));
                Ok(())
            }
            "security.owasp" => {
                let Some(register_path) = self.latest_result_register_path() else {
                    return Err("Latest result does not expose a JSON artifact path yet");
                };
                set_prompt_field(fields, "artifacts", &register_path);
                if let Some(case_dir) = result_case_dir {
                    set_prompt_field(fields, "case_dir", &case_dir);
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to map APK findings in {} to OWASP MASTG references.",
                        register_path
                    ),
                );
                Ok(())
            }
            "report.generate" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                let case_id = self
                    .latest_result_case_id()
                    .unwrap_or_else(|| derive_case_id_from_dir(&case_dir));
                set_prompt_field(fields, "case_dir", &case_dir);
                set_prompt_field(fields, "case_id", &case_id);
                if field_value(fields, "output") == Some("report.html") {
                    set_prompt_field(fields, "output", "");
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to report on {} · leave Output blank for case-managed reports/ paths.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "report.chain_of_custody" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                let case_id = self
                    .latest_result_case_id()
                    .unwrap_or_else(|| derive_case_id_from_dir(&case_dir));
                set_prompt_field(fields, "case_dir", &case_dir);
                set_prompt_field(fields, "case_id", &case_id);
                if field_value(fields, "output") == Some("chain_of_custody.txt") {
                    set_prompt_field(fields, "output", "");
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to derive chain-of-custody output for {} · leave Evidence blank to use the case manifest.",
                        case_dir
                    ),
                );
                Ok(())
            }
            "report.integrity" => {
                let Some(case_dir) = result_case_dir else {
                    return Err("Latest result does not expose a case directory yet");
                };
                set_prompt_field(fields, "case_dir", &case_dir);
                if field_value(fields, "output") == Some("integrity.json") {
                    set_prompt_field(fields, "output", "");
                }
                help_lines.insert(
                    0,
                    format!(
                        "Opened from Result view to verify registered artifacts in {} and write an operator-ready integrity report.",
                        case_dir
                    ),
                );
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
