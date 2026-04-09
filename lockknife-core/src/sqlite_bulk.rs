use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rusqlite::{Connection, OpenFlags};
use serde_json::json;

const MAX_LIMIT: u32 = 100_000;

fn open_readonly(path: &str) -> Result<Connection, rusqlite::Error> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
}

fn validate_table_name(table: &str) -> Result<(), PyErr> {
    if table.trim().is_empty() {
        return Err(PyValueError::new_err("table name is required"));
    }
    if table.len() > 64 {
        return Err(PyValueError::new_err("table name is too long"));
    }
    let mut chars = table.chars();
    let first = chars
        .next()
        .ok_or_else(|| PyValueError::new_err("table name is required"))?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(PyValueError::new_err("invalid table name"));
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(PyValueError::new_err("invalid table name"));
    }
    Ok(())
}

#[pyfunction]
pub fn sqlite_table_to_json(db_path: &str, table: &str, limit: u32) -> PyResult<String> {
    if limit == 0 {
        return Err(PyValueError::new_err("limit must be > 0"));
    }
    if limit > MAX_LIMIT {
        return Err(PyValueError::new_err("limit exceeds maximum"));
    }
    validate_table_name(table)?;
    let con = open_readonly(db_path).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let quoted = format!("\"{}\"", table);
    let pragma = format!("PRAGMA table_info({})", quoted);
    let mut stmt = con
        .prepare(&pragma)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| PyValueError::new_err(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();
    if cols.is_empty() {
        return Err(PyValueError::new_err("table not found or has no columns"));
    }

    let q = format!("SELECT * FROM {} LIMIT {}", quoted, limit);
    let mut stmt = con
        .prepare(&q)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let mut out = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|e| PyValueError::new_err(e.to_string()))?
    {
        let mut obj = serde_json::Map::new();
        for (i, name) in cols.iter().enumerate() {
            let v = row.get_ref_unwrap(i);
            let j = match v.data_type() {
                rusqlite::types::Type::Null => json!(null),
                rusqlite::types::Type::Integer => json!(v.as_i64().unwrap_or_default()),
                rusqlite::types::Type::Real => json!(v.as_f64().unwrap_or_default()),
                rusqlite::types::Type::Text => json!(v.as_str().unwrap_or("").to_string()),
                rusqlite::types::Type::Blob => json!(hex::encode(v.as_blob().unwrap_or(&[]))),
            };
            obj.insert(name.clone(), j);
        }
        out.push(serde_json::Value::Object(obj));
    }

    Ok(serde_json::to_string(&out).unwrap_or_else(|_| "[]".to_string()))
}

#[cfg(test)]
mod tests {
    use super::sqlite_table_to_json;
    use rusqlite::Connection;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Once;

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_db_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        let unique = format!(
            "lockknife_test_{}_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            counter,
        );
        path.push(unique);
        path
    }

    static INIT: Once = Once::new();

    fn init_python() {
        INIT.call_once(|| {
            pyo3::Python::initialize();
        });
    }

    #[test]
    fn test_sqlite_table_extracts_rows() {
        init_python();
        let path = temp_db_path();
        let conn = Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE demo(id INTEGER, name TEXT)", [])
            .unwrap();
        conn.execute("INSERT INTO demo(id, name) VALUES(1, 'a')", [])
            .unwrap();
        let out = sqlite_table_to_json(path.to_str().unwrap(), "demo", 10).unwrap();
        assert!(out.contains("\"id\""));
        assert!(out.contains("\"name\""));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_sqlite_table_empty_ok() {
        init_python();
        let path = temp_db_path();
        let conn = Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE demo(id INTEGER)", []).unwrap();
        let out = sqlite_table_to_json(path.to_str().unwrap(), "demo", 10).unwrap();
        assert!(out.contains("[]") || out.contains("{"));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_sqlite_table_missing_errors() {
        init_python();
        let path = temp_db_path();
        let conn = Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE demo(id INTEGER)", []).unwrap();
        let err = sqlite_table_to_json(path.to_str().unwrap(), "missing", 10).unwrap_err();
        assert!(format!("{err}").contains("table"));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_sqlite_injection_rejected() {
        init_python();
        let path = temp_db_path();
        let conn = Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE demo(id INTEGER)", []).unwrap();
        let err =
            sqlite_table_to_json(path.to_str().unwrap(), "demo; DROP TABLE demo;", 10).unwrap_err();
        assert!(format!("{err}").contains("invalid table"));
        fs::remove_file(path).ok();
    }
}
