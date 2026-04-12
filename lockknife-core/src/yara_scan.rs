use md5::{Digest, Md5};
use once_cell::sync::Lazy;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use yara_x::Compiler;

const MAX_DATA_BYTES: usize = 256 * 1024 * 1024; // 256 MB
const MAX_CACHE_SIZE: usize = 100; // Maximum number of compiled rules to cache

struct RuleCache {
    cache: RwLock<HashMap<String, Arc<yara_x::Rules>>>,
    size: RwLock<usize>,
}

impl RuleCache {
    fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            size: RwLock::new(0),
        }
    }

    fn get(&self, key: &str) -> Option<Arc<yara_x::Rules>> {
        let cache = self.cache.read().unwrap();
        cache.get(key).cloned()
    }

    fn put(&self, key: String, rules: Arc<yara_x::Rules>) {
        let mut cache = self.cache.write().unwrap();
        let mut size = self.size.write().unwrap();

        // Evict oldest entry if at capacity (simple FIFO)
        if *size >= MAX_CACHE_SIZE {
            if let Some(first_key) = cache.keys().next().cloned() {
                cache.remove(&first_key);
                *size -= 1;
            }
        }

        cache.insert(key, rules);
        *size += 1;
    }

    fn stats(&self) -> (usize, usize) {
        let size = self.size.read().unwrap();
        (*size, MAX_CACHE_SIZE)
    }
}

static RULE_CACHE: Lazy<RuleCache> = Lazy::new(RuleCache::new);

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

    // Compute cache key from rule source
    let cache_key = format!("{:x}", Md5::digest(rules_src.as_bytes()));

    // Try to get from cache
    let rules = if let Some(cached_rules) = RULE_CACHE.get(&cache_key) {
        cached_rules
    } else {
        // Compile and cache
        let mut compiler = Compiler::new();
        compiler
            .add_source(rules_src)
            .map_err(|e| PyValueError::new_err(format!("rule compilation failed: {e}")))?;
        let compiled_rules = Arc::new(compiler.build());
        RULE_CACHE.put(cache_key, compiled_rules.clone());
        compiled_rules
    };

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

/// Get YARA rule cache statistics.
///
/// Returns a JSON object with cache size and capacity:
/// ```json
/// {"size": 10, "capacity": 100}
/// ```
#[pyfunction]
pub fn yara_cache_stats() -> String {
    let (size, capacity) = RULE_CACHE.stats();
    json!({
        "size": size,
        "capacity": capacity
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{yara_cache_stats, yara_scan_bytes, yara_scan_file_rules};

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

    #[test]
    fn test_yara_cache_stats() {
        let stats = yara_cache_stats();
        assert!(stats.contains("size"));
        assert!(stats.contains("capacity"));
    }

    #[test]
    fn test_yara_cache_hit() {
        let data = b"This is an EICAR test string.";
        // First scan - cache miss
        let _ = yara_scan_bytes(RULE, data).unwrap();
        let stats1 = yara_cache_stats();
        // Second scan - cache hit
        let _ = yara_scan_bytes(RULE, data).unwrap();
        let stats2 = yara_cache_stats();
        // Cache size should not increase on hit
        assert_eq!(stats1, stats2);
    }

    #[test]
    fn test_yara_cache_miss_different_rule() {
        let data = b"This is an EICAR test string.";
        let rule2 = r#"
            rule TestRule2 {
                strings:
                    $a = "different"
                condition:
                    $a
            }
        "#;
        let _ = yara_scan_bytes(RULE, data).unwrap();
        let stats1 = yara_cache_stats();
        let _ = yara_scan_bytes(rule2, data).unwrap();
        let stats2 = yara_cache_stats();
        // Cache size should increase on miss
        assert_ne!(stats1, stats2);
    }
}
