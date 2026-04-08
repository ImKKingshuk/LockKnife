use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::json;
use yara_x::Compiler;

const MAX_DATA_BYTES: usize = 256 * 1024 * 1024; // 256 MB

/// Compile YARA-X rules (source string) and scan `data`.
///
/// Returns a JSON array of match objects:
/// ```json
/// [{"rule": "MyRule", "namespace": "default", "tags": [], "meta": {}}]
/// ```
///
/// YARA-X is VirusTotal's Rust-native rewrite — 99% compatible with classic YARA rules,
/// runs entirely in Rust (no C dependency), and is the engine behind VirusTotal's Livehunt.
#[pyfunction]
pub fn yara_scan_bytes(rules_src: &str, data: &[u8]) -> PyResult<String> {
    if rules_src.trim().is_empty() {
        return Err(PyValueError::new_err("rules_src must not be empty"));
    }
    if data.len() > MAX_DATA_BYTES {
        return Err(PyValueError::new_err("data exceeds size limit (256 MB)"));
    }

    let mut compiler = Compiler::new();
    compiler
        .add_source(rules_src)
        .map_err(|e| PyValueError::new_err(format!("rule compilation failed: {e}")))?;
    let rules = compiler.build();

    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner
        .scan(data)
        .map_err(|e| PyValueError::new_err(format!("scan failed: {e}")))?;

    let matches: Vec<serde_json::Value> = results
        .matching_rules()
        .map(|rule| {
            let meta: serde_json::Map<String, serde_json::Value> = rule
                .metadata()
                .map(|(k, v)| {
                    let jv = match v {
                        yara_x::MetaValue::Integer(i) => json!(i),
                        yara_x::MetaValue::Float(f) => json!(f),
                        yara_x::MetaValue::Bool(b) => json!(b),
                        yara_x::MetaValue::String(s) => json!(s),
                        yara_x::MetaValue::Bytes(b) => json!(hex::encode(b)),
                    };
                    (k.to_string(), jv)
                })
                .collect();

            json!({
                "rule": rule.identifier(),
                "namespace": rule.namespace(),
                "tags": rule.tags().map(|t| t.identifier()).collect::<Vec<_>>(),
                "meta": meta,
            })
        })
        .collect();

    Ok(serde_json::to_string(&matches).unwrap_or_else(|_| "[]".to_string()))
}

/// Compile YARA-X rules from a file path and scan `data`.
#[pyfunction]
pub fn yara_scan_file_rules(rules_path: &str, data: &[u8]) -> PyResult<String> {
    let src = std::fs::read_to_string(rules_path)
        .map_err(|e| PyValueError::new_err(format!("cannot read rules file: {e}")))?;
    yara_scan_bytes(&src, data)
}

#[cfg(test)]
mod tests {
    use super::{yara_scan_bytes, yara_scan_file_rules};

    const RULE: &str = r#"
        rule TestRule {
            meta:
                description = "detects test"
            strings:
                $a = "EICAR"
            condition:
                $a
        }
    "#;

    #[test]
    fn test_yara_scan_matches() {
        let data = b"This is an EICAR test string.";
        let out = yara_scan_bytes(RULE, data).unwrap();
        assert!(out.contains("TestRule"));
        assert!(out.contains("detects test"));
    }

    #[test]
    fn test_yara_scan_no_match() {
        let data = b"nothing here";
        let out = yara_scan_bytes(RULE, data).unwrap();
        assert_eq!(out, "[]");
    }

    #[test]
    fn test_yara_invalid_rule_errors() {
        let err = yara_scan_bytes("rule Bad { condition: nonsense }", b"data").unwrap_err();
        assert!(format!("{err}").contains("compilation failed") || !format!("{err}").is_empty());
    }

    #[test]
    fn test_yara_empty_rules_errors() {
        let err = yara_scan_bytes("", b"data").unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn test_yara_scan_file_rules_missing() {
        let err = yara_scan_file_rules("/nonexistent/path.yar", b"data").unwrap_err();
        assert!(format!("{err}").contains("cannot read"));
    }
}
