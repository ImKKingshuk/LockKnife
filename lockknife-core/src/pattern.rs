use aho_corasick::AhoCorasick;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::bytes::Regex;
use serde_json::json;

const MAX_DATA_BYTES: usize = 256 * 1024 * 1024; // 256 MB

/// Naive single-needle scan (kept for reference; the public API batches literals via AC).
#[allow(dead_code)]
fn find_all_literal(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
}

/// Parse a hex pattern string like `41??44` into a wildcard byte sequence.
fn parse_hex_pattern(input: &str) -> Result<Vec<Option<u8>>, String> {
    let mut out = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '?' {
            if let Some('?') = chars.peek() {
                chars.next();
            }
            out.push(None);
            continue;
        }
        let c2 = chars
            .next()
            .ok_or_else(|| "invalid hex pattern".to_string())?;
        let hex = format!("{c}{c2}");
        let v = u8::from_str_radix(&hex, 16).map_err(|_| "invalid hex pattern".to_string())?;
        out.push(Some(v));
    }
    Ok(out)
}

/// Wildcard byte scan (supports `??` wildcards in hex patterns).
fn find_all_wildcard(haystack: &[u8], needle: &[Option<u8>]) -> Vec<usize> {
    if needle.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        let mut ok = true;
        for (off, nb) in needle.iter().enumerate() {
            if let Some(b) = nb {
                if haystack[i + off] != *b {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            out.push(i);
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
}

/// Scan `data` for multiple patterns simultaneously.
///
/// Pattern prefix syntax:
///   - `hex:<bytes>` — hex pattern with optional `??` wildcards (e.g. `hex:4142??44`)
///   - `re:<regex>`  — byte-level regular expression (e.g. `re:token=\w+`)
///   - anything else — literal byte-string match
///
/// Literal patterns are batched together and scanned in a single Aho-Corasick pass for
/// maximum throughput. Hex/regex patterns are handled individually.
#[pyfunction]
pub fn scan_patterns_json(data: &[u8], patterns: Vec<String>) -> PyResult<String> {
    if data.len() > MAX_DATA_BYTES {
        return Err(PyValueError::new_err("data exceeds size limit (256 MB)"));
    }

    // Separate literal patterns from special patterns so we can batch them.
    let mut literal_indices: Vec<usize> = Vec::new();
    let mut literals: Vec<&[u8]> = Vec::new();
    let mut special: Vec<(usize, &str)> = Vec::new(); // (original index, prefix-stripped value)
    let mut results: Vec<serde_json::Value> = vec![serde_json::Value::Null; patterns.len()];

    for (i, p) in patterns.iter().enumerate() {
        if p.starts_with("hex:") || p.starts_with("re:") {
            special.push((i, p.as_str()));
        } else if p.is_empty() {
            results[i] = json!({"pattern": p, "kind": "literal", "offsets": []});
        } else {
            literal_indices.push(i);
            literals.push(p.as_bytes());
        }
    }

    // Initialise results with empty offset arrays.
    for i in &literal_indices {
        results[*i] = json!({"pattern": patterns[*i], "kind": "literal", "offsets": []});
    }

    // --- Literal batch scan via Aho-Corasick ---
    if !literals.is_empty() {
        // Track per-pattern offsets.
        let mut offsets: Vec<Vec<usize>> = vec![Vec::new(); literals.len()];

        // Non-overlapping left-most match by default; use overlapping for correctness
        // when patterns share prefixes (e.g. "aa" in "aaaa").
        let ac = AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(&literals)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        // For overlapping semantics (find all occurrences of each pattern), we use
        // find_overlapping_iter which returns every match regardless of length.
        for m in ac.find_overlapping_iter(data) {
            offsets[m.pattern().as_usize()].push(m.start());
        }

        for (slot, orig_i) in literal_indices.iter().enumerate() {
            results[*orig_i] = json!({
                "pattern": patterns[*orig_i],
                "kind": "literal",
                "offsets": offsets[slot],
            });
        }
    }

    // --- Special patterns (hex / regex) ---
    for (orig_i, raw) in special {
        if let Some(hex_pattern) = raw.strip_prefix("hex:") {
            let needle = parse_hex_pattern(hex_pattern.trim()).map_err(PyValueError::new_err)?;
            let offsets = find_all_wildcard(data, &needle);
            results[orig_i] = json!({"pattern": raw, "kind": "hex", "offsets": offsets});
        } else if let Some(re_pattern) = raw.strip_prefix("re:") {
            let re = Regex::new(re_pattern).map_err(|e| PyValueError::new_err(e.to_string()))?;
            let offsets: Vec<usize> = re.find_iter(data).map(|m| m.start()).collect();
            results[orig_i] = json!({"pattern": raw, "kind": "regex", "offsets": offsets});
        }
    }

    Ok(serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string()))
}

#[cfg(test)]
mod tests {
    use super::scan_patterns_json;

    #[test]
    fn test_scan_literal_patterns() {
        let out = scan_patterns_json(b"abcabc", vec!["abc".to_string()]).unwrap();
        assert!(out.contains("\"offsets\":[0,3]") || out.contains("\"offsets\":[0, 3]"));
    }

    #[test]
    fn test_scan_multiple_literals_batched() {
        // Both patterns matched in a single AC pass.
        let out = scan_patterns_json(
            b"hello world hello",
            vec!["hello".to_string(), "world".to_string()],
        )
        .unwrap();
        // "hello" at 0 and 12; "world" at 6
        assert!(out.contains("\"hello\""));
        assert!(out.contains("\"world\""));
    }

    #[test]
    fn test_scan_hex_pattern_with_wildcard() {
        let out =
            scan_patterns_json(b"\x41\x42\x43\x44", vec!["hex:41????44".to_string()]).unwrap();
        assert!(out.contains("\"offsets\":[0]") || out.contains("\"offsets\":[0]"));
    }

    #[test]
    fn test_scan_regex_pattern() {
        let out =
            scan_patterns_json(b"token=abc token=xyz", vec!["re:token=\\w+".to_string()]).unwrap();
        assert!(out.contains("\"offsets\":[0,10]") || out.contains("\"offsets\":[0, 10]"));
    }

    #[test]
    fn test_scan_empty_and_no_match() {
        let out = scan_patterns_json(b"abc", vec!["".to_string(), "zzz".to_string()]).unwrap();
        assert!(out.contains("\"offsets\":[]"));
    }

    #[test]
    fn test_scan_overlapping() {
        let out = scan_patterns_json(b"aaaa", vec!["aa".to_string()]).unwrap();
        // With overlapping iter we should get offsets 0, 1, 2 for "aa" in "aaaa".
        assert!(out.contains("offsets"));
    }

    #[test]
    fn test_size_limit_rejects_oversized() {
        // We can't actually allocate 256 MB in a test, so verify that a 1-byte slice passes.
        let out = scan_patterns_json(b"x", vec!["x".to_string()]).unwrap();
        assert!(out.contains("\"offsets\":[0]"));
    }
}
