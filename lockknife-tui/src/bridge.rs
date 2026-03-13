use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct CallbackLog {
    pub level: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct CallbackResult {
    pub ok: bool,
    pub message: Option<String>,
    pub data_json: Option<String>,
    pub job_json: Option<String>,
    pub logs: Option<Vec<CallbackLog>>,
    pub error: Option<String>,
}

impl CallbackResult {
    pub fn error_message(&self) -> String {
        self.error
            .clone()
            .unwrap_or_else(|| "Operation failed".to_string())
    }
}

pub fn call(callback: &Py<PyAny>, action: &str, params: &Value) -> CallbackResult {
    Python::with_gil(|py| {
        let callable = callback.bind(py);
        let params_obj = to_pyobject(py, params);
        let args = (action, params_obj);
        match callable.call1(args) {
            Ok(value) => parse_result(&value),
            Err(err) => CallbackResult {
                ok: false,
                message: None,
                data_json: None,
                job_json: None,
                logs: None,
                error: Some(err.to_string()),
            },
        }
    })
}

fn parse_result(value: &Bound<'_, PyAny>) -> CallbackResult {
    let mut ok = false;
    let mut message = None;
    let mut data_json = None;
    let mut job_json = None;
    let mut logs = None;
    let mut error = None;

    if let Ok(dict) = value.downcast::<PyDict>() {
        if let Ok(Some(v)) = dict.get_item("ok") {
            if let Ok(b) = v.extract::<bool>() {
                ok = b;
            }
        }
        if let Ok(Some(v)) = dict.get_item("message") {
            if let Ok(s) = v.extract::<String>() {
                message = Some(s);
            }
        }
        if let Ok(Some(v)) = dict.get_item("data_json") {
            if let Ok(s) = v.extract::<String>() {
                data_json = Some(s);
            }
        }
        if let Ok(Some(v)) = dict.get_item("job_json") {
            if let Ok(s) = v.extract::<String>() {
                job_json = Some(s);
            }
        }
        if let Ok(Some(v)) = dict.get_item("error") {
            if let Ok(s) = v.extract::<String>() {
                error = Some(s);
            }
        }
        if let Ok(Some(v)) = dict.get_item("logs") {
            if let Ok(list) = v.downcast::<PyList>() {
                let mut out = Vec::new();
                for item in list.iter() {
                    if let Ok(log_dict) = item.downcast::<PyDict>() {
                        let mut level = "info".to_string();
                        if let Ok(Some(v)) = log_dict.get_item("level") {
                            if let Ok(s) = v.extract::<String>() {
                                level = s;
                            }
                        }
                        let mut message = String::new();
                        if let Ok(Some(v)) = log_dict.get_item("message") {
                            if let Ok(s) = v.extract::<String>() {
                                message = s;
                            }
                        }
                        if !message.is_empty() {
                            out.push(CallbackLog { level, message });
                        }
                    }
                }
                if !out.is_empty() {
                    logs = Some(out);
                }
            }
        }
    }

    CallbackResult {
        ok,
        message,
        data_json,
        job_json,
        logs,
        error,
    }
}

fn to_pyobject(py: Python<'_>, value: &Value) -> PyObject {
    match value {
        Value::Null => py.None(),
        Value::Bool(b) => b.into_py(py),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_py(py)
            } else if let Some(u) = n.as_u64() {
                u.into_py(py)
            } else if let Some(f) = n.as_f64() {
                f.into_py(py)
            } else {
                py.None()
            }
        }
        Value::String(s) => s.into_py(py),
        Value::Array(arr) => {
            let list = PyList::empty_bound(py);
            for v in arr {
                list.append(to_pyobject(py, v)).ok();
            }
            list.into_py(py)
        }
        Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in map {
                dict.set_item(k, to_pyobject(py, v)).ok();
            }
            dict.into_py(py)
        }
    }
}
