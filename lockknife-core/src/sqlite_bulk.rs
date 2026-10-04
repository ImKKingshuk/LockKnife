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
pub fn sqlite_table_to_json(
    py: Python<'_>,
    db_path: &str,
    table: &str,
    limit: u32,
) -> PyResult<String> {
    if limit == 0 {
        return Err(PyValueError::new_err("limit must be > 0"));
    }
    if limit > MAX_LIMIT {
        return Err(PyValueError::new_err("limit exceeds maximum"));
    }
    validate_table_name(table)?;
    let db_path = db_path.to_string();
    let table = table.to_string();

    py.detach(move || {
        let con = open_readonly(&db_path).map_err(|e| PyValueError::new_err(e.to_string()))?;
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
    })
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CarvedRecord {
    pub page_number: u32,
    pub offset: usize,
    pub source: String,
    pub columns: Vec<serde_json::Value>,
}

fn read_varint(data: &[u8], mut offset: usize) -> Option<(u64, usize)> {
    if offset >= data.len() {
        return None;
    }
    let mut result: u64 = 0;
    for i in 0..8 {
        if offset >= data.len() {
            return None;
        }
        let byte = data[offset];
        offset += 1;
        result = (result << 7) | ((byte & 0x7F) as u64);
        if (byte & 0x80) == 0 {
            return Some((result, offset));
        }
        if i == 7 {
            if offset >= data.len() {
                return None;
            }
            let byte9 = data[offset];
            offset += 1;
            result = (result << 8) | (byte9 as u64);
            return Some((result, offset));
        }
    }
    None
}

fn serial_type_length(st: u64) -> Option<usize> {
    match st {
        0 | 8 | 9 => Some(0),
        1 => Some(1),
        2 => Some(2),
        3 => Some(3),
        4 => Some(4),
        5 => Some(6),
        6 | 7 => Some(8),
        10 | 11 => None,
        n if n >= 12 && n % 2 == 0 => Some(((n - 12) / 2) as usize),
        n if n >= 13 && n % 2 == 1 => Some(((n - 13) / 2) as usize),
        _ => None,
    }
}

fn decode_serial_value(st: u64, slice: &[u8]) -> Option<serde_json::Value> {
    match st {
        0 => Some(serde_json::Value::Null),
        1 => Some(json!(slice.first().copied()? as i8)),
        2 => {
            let arr: [u8; 2] = slice.try_into().ok()?;
            Some(json!(i16::from_be_bytes(arr) as i64))
        }
        3 => {
            if slice.len() != 3 {
                return None;
            }
            let val = ((slice[0] as i8 as i32) << 16) | ((slice[1] as i32) << 8) | (slice[2] as i32);
            Some(json!(val as i64))
        }
        4 => {
            let arr: [u8; 4] = slice.try_into().ok()?;
            Some(json!(i32::from_be_bytes(arr) as i64))
        }
        5 => {
            if slice.len() != 6 {
                return None;
            }
            let mut buf = [0u8; 8];
            buf[2..8].copy_from_slice(slice);
            if (slice[0] & 0x80) != 0 {
                buf[0] = 0xFF;
                buf[1] = 0xFF;
            }
            Some(json!(i64::from_be_bytes(buf)))
        }
        6 => {
            let arr: [u8; 8] = slice.try_into().ok()?;
            Some(json!(i64::from_be_bytes(arr)))
        }
        7 => {
            let arr: [u8; 8] = slice.try_into().ok()?;
            let f = f64::from_be_bytes(arr);
            if f.is_nan() || f.is_infinite() {
                None
            } else {
                Some(json!(f))
            }
        }
        8 => Some(json!(0)),
        9 => Some(json!(1)),
        n if n >= 12 && n % 2 == 0 => Some(json!(hex::encode(slice))),
        n if n >= 13 && n % 2 == 1 => {
            let s = std::str::from_utf8(slice).ok()?;
            Some(json!(s))
        }
        _ => None,
    }
}

fn parse_sqlite_record(data: &[u8], offset: usize) -> Option<(Vec<serde_json::Value>, usize)> {
    if offset >= data.len() {
        return None;
    }
    let (header_size_u64, mut cursor) = read_varint(data, offset)?;
    let header_size = header_size_u64 as usize;
    if header_size < 2 || header_size > 2048 {
        return None;
    }
    let header_end = offset.checked_add(header_size)?;
    if header_end > data.len() {
        return None;
    }

    let mut serial_types: Vec<u64> = Vec::new();
    while cursor < header_end {
        let (st, next_cursor) = read_varint(data, cursor)?;
        if next_cursor > header_end {
            return None;
        }
        if st == 10 || st == 11 {
            return None;
        }
        serial_types.push(st);
        cursor = next_cursor;
    }

    if serial_types.is_empty() || serial_types.len() > 128 {
        return None;
    }

    let mut body_cursor = header_end;
    let mut columns: Vec<serde_json::Value> = Vec::with_capacity(serial_types.len());
    let mut has_meaningful_content = false;

    for st in serial_types {
        let val_len = serial_type_length(st)?;
        let val_end = body_cursor.checked_add(val_len)?;
        if val_end > data.len() {
            return None;
        }
        let val_slice = &data[body_cursor..val_end];
        body_cursor = val_end;

        let val = decode_serial_value(st, val_slice)?;
        match &val {
            serde_json::Value::String(s) => {
                if s.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
                    return None;
                }
                if s.trim().len() >= 2 {
                    has_meaningful_content = true;
                }
            }
            serde_json::Value::Number(n) => {
                if n.as_i64().map_or(false, |v| v != 0) || n.as_f64().map_or(false, |v| v != 0.0) {
                    has_meaningful_content = true;
                }
            }
            serde_json::Value::Bool(_) => {
                has_meaningful_content = true;
            }
            _ => {}
        }
        columns.push(val);
    }

    if !has_meaningful_content {
        return None;
    }

    let total_consumed = body_cursor - offset;
    Some((columns, total_consumed))
}

fn try_carve_record_at(data: &[u8], offset: usize) -> Option<(Vec<serde_json::Value>, usize)> {
    if let Some((cols, len)) = parse_sqlite_record(data, offset) {
        return Some((cols, len));
    }
    if let Some((payload_size, after_ps)) = read_varint(data, offset) {
        if payload_size > 0 && payload_size <= 65536 {
            if let Some((_rowid, after_rowid)) = read_varint(data, after_ps) {
                if let Some((cols, rec_len)) = parse_sqlite_record(data, after_rowid) {
                    return Some((cols, (after_rowid - offset) + rec_len));
                }
            }
        }
    }
    None
}

pub fn carve_sqlite_bytes(raw: &[u8], max_records: usize) -> Vec<CarvedRecord> {
    if raw.len() < 100 || !raw.starts_with(b"SQLite format 3\0") {
        return Vec::new();
    }
    let ps = u16::from_be_bytes([raw[16], raw[17]]) as usize;
    let page_size = if ps == 1 { 65536 } else { ps };
    if page_size < 512 || (page_size & (page_size - 1)) != 0 {
        return Vec::new();
    }

    let total_pages = raw.len() / page_size;
    if total_pages == 0 {
        return Vec::new();
    }

    let freelist_trunk = if raw.len() >= 36 {
        u32::from_be_bytes(raw[32..36].try_into().unwrap_or([0; 4])) as usize
    } else {
        0
    };

    let mut freelist_pages: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut trunk = freelist_trunk;
    let mut visited_trunks = std::collections::HashSet::new();
    while trunk > 0 && trunk <= total_pages && visited_trunks.insert(trunk) {
        freelist_pages.insert(trunk);
        let trunk_offset = (trunk - 1) * page_size;
        if trunk_offset + 8 <= raw.len() {
            let next_trunk =
                u32::from_be_bytes(raw[trunk_offset..trunk_offset + 4].try_into().unwrap_or([0; 4]))
                    as usize;
            let leaf_count =
                u32::from_be_bytes(raw[trunk_offset + 4..trunk_offset + 8].try_into().unwrap_or([0; 4]))
                    as usize;
            let max_leaves = (page_size - 8) / 4;
            let actual_leaves = leaf_count.min(max_leaves);
            for i in 0..actual_leaves {
                let ptr_offset = trunk_offset + 8 + i * 4;
                if ptr_offset + 4 <= raw.len() {
                    let leaf =
                        u32::from_be_bytes(raw[ptr_offset..ptr_offset + 4].try_into().unwrap_or([0; 4]))
                            as usize;
                    if leaf > 0 && leaf <= total_pages {
                        freelist_pages.insert(leaf);
                    }
                }
            }
            trunk = next_trunk;
        } else {
            break;
        }
    }

    let mut out: Vec<CarvedRecord> = Vec::new();
    let mut seen_sigs: std::collections::HashSet<String> = std::collections::HashSet::new();

    for page_num in 1..=total_pages {
        if out.len() >= max_records {
            break;
        }
        let page_offset = (page_num - 1) * page_size;
        let page_end = page_offset + page_size;
        if page_end > raw.len() {
            break;
        }
        let page_data = &raw[page_offset..page_end];
        let is_freelist = freelist_pages.contains(&page_num);

        if is_freelist {
            let mut off = 0;
            while off + 4 <= page_size && out.len() < max_records {
                if let Some((cols, len)) = try_carve_record_at(page_data, off) {
                    let sig = serde_json::to_string(&cols).unwrap_or_default();
                    if seen_sigs.insert(sig) {
                        out.push(CarvedRecord {
                            page_number: page_num as u32,
                            offset: page_offset + off,
                            source: "freelist".to_string(),
                            columns: cols,
                        });
                    }
                    off += len.max(1);
                } else {
                    off += 1;
                }
            }
            continue;
        }

        let hdr_offset = if page_num == 1 { 100 } else { 0 };
        if hdr_offset + 8 > page_size {
            continue;
        }

        let flag = page_data[hdr_offset];
        if flag == 0x0D {
            let freeblock_offset =
                u16::from_be_bytes([page_data[hdr_offset + 1], page_data[hdr_offset + 2]]) as usize;
            let cell_count =
                u16::from_be_bytes([page_data[hdr_offset + 3], page_data[hdr_offset + 4]]) as usize;
            let mut cell_content_offset =
                u16::from_be_bytes([page_data[hdr_offset + 5], page_data[hdr_offset + 6]]) as usize;
            if cell_content_offset == 0 {
                cell_content_offset = 65536;
            }

            let cell_pointers_end = hdr_offset + 8 + 2 * cell_count;
            let mut is_active_cell = vec![false; page_size];

            for i in 0..cell_count {
                let ptr_off = hdr_offset + 8 + 2 * i;
                if ptr_off + 2 <= page_size {
                    let ptr = u16::from_be_bytes([page_data[ptr_off], page_data[ptr_off + 1]]) as usize;
                    if ptr < page_size {
                        if let Some((_cols, clen)) = try_carve_record_at(page_data, ptr) {
                            for b in ptr..(ptr + clen).min(page_size) {
                                is_active_cell[b] = true;
                            }
                        } else {
                            is_active_cell[ptr] = true;
                        }
                    }
                }
            }

            // 1. Traverse freeblock chain
            let mut fb = freeblock_offset;
            let mut visited_fb = std::collections::HashSet::new();
            while fb > 0 && fb + 4 <= page_size && visited_fb.insert(fb) && out.len() < max_records {
                let next_fb = u16::from_be_bytes([page_data[fb], page_data[fb + 1]]) as usize;
                let fb_len = u16::from_be_bytes([page_data[fb + 2], page_data[fb + 3]]) as usize;
                let scan_limit = (fb + fb_len).min(page_size);

                let mut cur = fb + 4;
                while cur + 2 <= scan_limit && out.len() < max_records {
                    if let Some((cols, len)) = try_carve_record_at(page_data, cur) {
                        let sig = serde_json::to_string(&cols).unwrap_or_default();
                        if seen_sigs.insert(sig) {
                            out.push(CarvedRecord {
                                page_number: page_num as u32,
                                offset: page_offset + cur,
                                source: "freeblock".to_string(),
                                columns: cols,
                            });
                        }
                        cur += len.max(1);
                    } else {
                        cur += 1;
                    }
                }
                fb = next_fb;
            }

            // 2. Scan unallocated space between cell pointers and cell content
            let unalloc_end = cell_content_offset.min(page_size);
            if cell_pointers_end < unalloc_end {
                let mut cur = cell_pointers_end;
                while cur + 2 <= unalloc_end && out.len() < max_records {
                    if let Some((cols, len)) = try_carve_record_at(page_data, cur) {
                        let sig = serde_json::to_string(&cols).unwrap_or_default();
                        if seen_sigs.insert(sig) {
                            out.push(CarvedRecord {
                                page_number: page_num as u32,
                                offset: page_offset + cur,
                                source: "unallocated".to_string(),
                                columns: cols,
                            });
                        }
                        cur += len.max(1);
                    } else {
                        cur += 1;
                    }
                }
            }

            // 3. Scan inactive gaps inside cell content area (deleted cells)
            let mut cur = cell_content_offset.min(page_size);
            while cur + 2 <= page_size && out.len() < max_records {
                if !is_active_cell[cur] {
                    if let Some((cols, len)) = try_carve_record_at(page_data, cur) {
                        let sig = serde_json::to_string(&cols).unwrap_or_default();
                        if seen_sigs.insert(sig) {
                            out.push(CarvedRecord {
                                page_number: page_num as u32,
                                offset: page_offset + cur,
                                source: "deleted_cell".to_string(),
                                columns: cols,
                            });
                        }
                        cur += len.max(1);
                        continue;
                    }
                }
                cur += 1;
            }
        }
    }

    out
}

#[pyfunction]
pub fn sqlite_carve_records(
    py: Python<'_>,
    db_path: &str,
    max_records: u32,
) -> PyResult<String> {
    if max_records == 0 {
        return Err(PyValueError::new_err("max_records must be > 0"));
    }
    let db_path = db_path.to_string();
    py.detach(move || {
        let raw = std::fs::read(&db_path)
            .map_err(|e| PyValueError::new_err(format!("Failed to read database file: {e}")))?;
        let records = carve_sqlite_bytes(&raw, max_records as usize);
        serde_json::to_string(&records)
            .map_err(|e| PyValueError::new_err(format!("Serialization error: {e}")))
    })
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
        let out = pyo3::Python::attach(|py| {
            sqlite_table_to_json(py, path.to_str().unwrap(), "demo", 10).unwrap()
        });
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
        let out = pyo3::Python::attach(|py| {
            sqlite_table_to_json(py, path.to_str().unwrap(), "demo", 10).unwrap()
        });
        assert!(out.contains("[]") || out.contains("{"));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_sqlite_table_missing_errors() {
        init_python();
        let path = temp_db_path();
        let conn = Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE demo(id INTEGER)", []).unwrap();
        let err = pyo3::Python::attach(|py| {
            sqlite_table_to_json(py, path.to_str().unwrap(), "missing", 10).unwrap_err()
        });
        assert!(format!("{err}").contains("table"));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_sqlite_injection_rejected() {
        init_python();
        let path = temp_db_path();
        let conn = Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE demo(id INTEGER)", []).unwrap();
        let err = pyo3::Python::attach(|py| {
            sqlite_table_to_json(py, path.to_str().unwrap(), "demo; DROP TABLE demo;", 10)
                .unwrap_err()
        });
        assert!(format!("{err}").contains("invalid table"));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_varint_and_serial_decoders() {
        use super::{decode_serial_value, read_varint, serial_type_length};
        // 1-byte varint
        assert_eq!(read_varint(&[0x2A], 0), Some((42, 1)));
        // 2-byte varint: 0x81, 0x01 => (1 << 7) | 1 = 129
        assert_eq!(read_varint(&[0x81, 0x01], 0), Some((129, 2)));

        // Serial lengths
        assert_eq!(serial_type_length(0), Some(0)); // NULL
        assert_eq!(serial_type_length(1), Some(1)); // 8-bit int
        assert_eq!(serial_type_length(4), Some(4)); // 32-bit int
        assert_eq!(serial_type_length(6), Some(8)); // 64-bit int
        assert_eq!(serial_type_length(13), Some(0)); // Empty text
        assert_eq!(serial_type_length(23), Some(5)); // Text of length (23 - 13) / 2 = 5
        assert_eq!(serial_type_length(14), Some(1)); // Blob of length (14 - 12) / 2 = 1

        // Decode text
        let text_bytes = b"hello";
        let val = decode_serial_value(23, text_bytes).unwrap();
        assert_eq!(val, serde_json::json!("hello"));

        // Decode int
        let int_bytes = [0x00, 0x00, 0x01, 0x00];
        let ival = decode_serial_value(4, &int_bytes).unwrap();
        assert_eq!(ival, serde_json::json!(256));
    }

    #[test]
    fn test_carve_deleted_records_from_db() {
        use super::sqlite_carve_records;
        init_python();
        let path = temp_db_path();
        let conn = Connection::open(&path).unwrap();
        conn.execute("PRAGMA auto_vacuum = NONE", []).unwrap();
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (username, email) VALUES ('forensic_target_alice', 'alice@classified.org')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (username, email) VALUES ('forensic_target_bob', 'bob@classified.org')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (username, email) VALUES ('forensic_target_charlie', 'charlie@classified.org')",
            [],
        )
        .unwrap();
        // Delete records so they enter freeblocks / unallocated space
        conn.execute("DELETE FROM users WHERE username = 'forensic_target_bob'", []).unwrap();
        conn.execute("DELETE FROM users WHERE username = 'forensic_target_alice'", []).unwrap();

        let json_str = pyo3::Python::attach(|py| {
            sqlite_carve_records(py, path.to_str().unwrap(), 100).unwrap()
        });

        assert!(
            json_str.contains("forensic_target_bob")
                || json_str.contains("bob@classified.org")
                || json_str.contains("forensic_target_alice")
                || json_str.contains("alice@classified.org"),
            "Carved records should recover deleted row content: {}",
            json_str
        );
        fs::remove_file(path).ok();
    }
}
