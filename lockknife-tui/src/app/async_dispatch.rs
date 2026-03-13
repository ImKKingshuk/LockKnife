use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use pyo3::Python;
use serde_json::Value;

use crate::bridge::{self, CallbackResult};

use super::results::extract_result_paths;
use super::*;

impl App {
    pub fn refresh_devices(&mut self) {
        self.push_log("info", "Refreshing devices...");
        let params = Value::Object(serde_json::Map::new());
        let result = bridge::call(&self.callback, "device.list", &params);
        self.apply_result("device.list", result);
    }

    pub fn tick(&mut self) {
        if self.last_tick.elapsed() >= Duration::from_millis(120) {
            self.spinner_index = (self.spinner_index + 1) % 4;
            self.last_tick = Instant::now();
        }
        self.prune_toasts();
    }

    pub fn selected_device_serial(&self) -> Option<String> {
        self.devices
            .get(self.selected_device)
            .map(|d| d.serial.clone())
    }

    pub fn push_log(&mut self, level: &str, message: impl Into<String>) {
        let entry = LogEntry {
            timestamp: now_hms(),
            level: level.to_string(),
            message: message.into(),
        };
        self.logs.push(entry);
        if self.logs.len() > 5000 {
            self.logs.drain(0..self.logs.len().saturating_sub(5000));
        }
    }

    pub fn push_toast(&mut self, level: &str, message: impl Into<String>) {
        self.toasts.push(Toast {
            created_at: Instant::now(),
            level: level.to_string(),
            message: message.into(),
        });
        if self.toasts.len() > 6 {
            self.toasts.drain(0..self.toasts.len().saturating_sub(6));
        }
    }

    pub(crate) fn push_feedback(&mut self, level: &str, message: impl Into<String>) {
        let message = message.into();
        self.push_log(level, message.clone());
        self.push_toast(level, message);
    }

    pub fn prune_toasts(&mut self) {
        let now = Instant::now();
        self.toasts
            .retain(|t| now.duration_since(t.created_at) < Duration::from_secs(3));
    }

    pub fn poll_async(&mut self) {
        if let Some(rx) = &self.async_rx {
            if let Ok(res) = rx.try_recv() {
                self.async_rx = None;
                self.cancel_tx = None;
                self.busy = false;
                self.progress = 100;
                self.apply_result(&res.action, res.result);
            }
        }
    }

    pub fn cancel_async(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
        self.async_rx = None;
        self.busy = false;
        self.progress = 0;
        self.progress_label = String::new();
    }

    pub fn execute_action(&mut self, module_index: usize, action_index: usize, params: Value) {
        let Some(module) = self.modules.get(module_index) else {
            return;
        };
        let Some(action) = module.actions.get(action_index) else {
            return;
        };
        let action_id = action.id.clone();
        let action_label = action.label.clone();
        let requires_device = action.requires_device;
        if requires_device && self.selected_device_serial().is_none() {
            self.push_feedback("error", "No device selected");
            return;
        }
        if self.busy {
            self.push_feedback("warn", "Operation already running");
            return;
        }
        let mut payload = params;
        self.remember_prompt_defaults_from_params(&payload);
        if action_id == "case.artifacts" {
            self.remember_artifact_filter_history_from_params(&payload);
        }
        self.pending_case_dir = case_dir_from_value(&payload);
        if action_id == "report.generate" {
            if let Value::Object(map) = &mut payload {
                let artifacts = map.get("artifacts").and_then(|v| v.as_str()).unwrap_or("");
                if artifacts.is_empty() {
                    let target_case = map
                        .get("case_dir")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string);
                    let latest_case = self.last_result_case_dir();
                    if let Some(data_json) = self.last_result_json.clone().filter(|_| {
                        target_case.is_none() || latest_case.as_deref() == target_case.as_deref()
                    }) {
                        map.insert("data_json".to_string(), Value::String(data_json));
                    }
                }
            }
        }
        if requires_device {
            if let Some(serial) = self.selected_device_serial() {
                if let Value::Object(map) = &mut payload {
                    map.insert("serial".to_string(), Value::String(serial));
                }
            }
        }
        self.spawn_async(action_id, action_label, payload);
    }

    pub fn execute_custom(&mut self, action: &str, params: Value) {
        if self.busy {
            self.push_feedback("warn", "Operation already running");
            return;
        }
        self.pending_case_dir = case_dir_from_value(&params);
        self.spawn_async(action.to_string(), action.to_string(), params);
    }

    fn spawn_async(&mut self, action_id: String, label: String, payload: Value) {
        let (tx, rx): (Sender<AsyncResult>, Receiver<AsyncResult>) = mpsc::channel();
        let (cancel_tx, cancel_rx): (Sender<()>, Receiver<()>) = mpsc::channel();
        let callback = Python::with_gil(|py| self.callback.clone_ref(py));
        self.busy = true;
        self.progress = 10;
        self.progress_label = label;
        self.async_rx = Some(rx);
        self.cancel_tx = Some(cancel_tx);
        thread::spawn(move || {
            if cancel_rx.try_recv().is_ok() {
                return;
            }
            let result = match catch_unwind(AssertUnwindSafe(|| {
                bridge::call(&callback, &action_id, &payload)
            })) {
                Ok(res) => res,
                Err(_) => CallbackResult {
                    ok: false,
                    message: None,
                    data_json: None,
                    job_json: None,
                    logs: None,
                    error: Some("Async operation panicked".to_string()),
                },
            };
            if cancel_rx.try_recv().is_ok() {
                return;
            }
            let _ = tx.send(AsyncResult {
                action: action_id,
                result,
            });
        });
    }

    pub fn apply_result(&mut self, action: &str, result: CallbackResult) {
        let result_job = result.job_json.clone();
        if result.ok {
            let result_message = result
                .message
                .clone()
                .filter(|message| !message.trim().is_empty());
            let result_data = result.data_json.clone();
            let mut fallback_message = None;
            if let Some(logs) = result.logs {
                for log in logs {
                    self.push_log(&log.level, log.message);
                }
            }
            if let Some(message) = result_message.clone() {
                self.push_log("info", message.clone());
                self.push_toast("info", message);
            }
            self.last_result_message = result_message.clone();
            self.last_result_paths =
                extract_result_paths(result_message.as_deref(), result_data.as_deref());
            self.last_job_json = result_job;
            self.promote_case_context(action, result_data.as_deref());
            self.record_investigation_result(
                action,
                true,
                result_message.as_deref(),
                result_data.as_deref(),
                None,
            );
            for path in self.last_result_paths.clone() {
                self.push_log("info", format!("↳ {}: {}", path.label, path.value));
            }
            if action == "config.save" {
                self.config_saved_text = self.config_text.clone();
            }
            if let Some(data) = result_data {
                self.last_result_json = Some(data.clone());
                if action == "device.list" {
                    if let Ok(value) = serde_json::from_str::<Value>(&data) {
                        if let Some(items) = value.as_array() {
                            let mut devices = Vec::new();
                            for item in items {
                                if let Some(obj) = item.as_object() {
                                    let serial = obj
                                        .get("serial")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    if serial.is_empty() {
                                        continue;
                                    }
                                    let adb_state = obj
                                        .get("adb_state")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let state = obj
                                        .get("state")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let model = obj
                                        .get("model")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    let device = obj
                                        .get("device")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    let transport_id = obj
                                        .get("transport_id")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    devices.push(DeviceItem {
                                        serial,
                                        adb_state,
                                        state,
                                        model,
                                        device,
                                        transport_id,
                                    });
                                }
                            }
                            self.devices = devices;
                            if self.selected_device >= self.devices.len() {
                                self.selected_device = self.devices.len().saturating_sub(1);
                            }
                            fallback_message = Some(device_refresh_feedback(self.devices.len()));
                        }
                    }
                }
            }
            self.pending_case_dir = None;
            if result_message.is_none() {
                if fallback_message.is_none() {
                    fallback_message =
                        success_feedback_message(action, self.config_path.as_deref());
                }
                if let Some(message) = fallback_message {
                    self.push_feedback("info", message);
                }
            }
        } else {
            self.pending_case_dir = None;
            let error_message = result.error_message();
            self.last_job_json = result_job;
            if let Some(data) = result.data_json.clone() {
                self.last_result_json = Some(data);
            }
            if let Some(logs) = result.logs {
                for log in logs {
                    self.push_log(&log.level, log.message);
                }
            }
            self.push_feedback("error", &error_message);
            self.record_investigation_result(
                action,
                false,
                None,
                result.data_json.as_deref(),
                Some(&error_message),
            );
            if let Some(recovery_hint) = self.action_failure_recovery_hint(action) {
                self.push_log("warn", recovery_hint.to_string());
                self.push_toast("warn", recovery_hint.to_string());
            }
        }
    }
}
