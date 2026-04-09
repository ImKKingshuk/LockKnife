use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use ring::digest;

fn parse_gesture_key_sha1(raw: &[u8]) -> Option<[u8; 20]> {
    if raw.len() >= 20 {
        let mut out = [0u8; 20];
        out.copy_from_slice(&raw[..20]);
        return Some(out);
    }
    None
}

fn sha1_pattern_bytes(pattern: &[u8]) -> [u8; 20] {
    let d = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, pattern);
    let mut out = [0u8; 20];
    out.copy_from_slice(d.as_ref());
    out
}

fn jump_table() -> [[u8; 10]; 10] {
    let mut j = [[0u8; 10]; 10];
    j[1][3] = 2;
    j[3][1] = 2;
    j[1][7] = 4;
    j[7][1] = 4;
    j[3][9] = 6;
    j[9][3] = 6;
    j[7][9] = 8;
    j[9][7] = 8;
    j[1][9] = 5;
    j[9][1] = 5;
    j[3][7] = 5;
    j[7][3] = 5;
    j[4][6] = 5;
    j[6][4] = 5;
    j[2][8] = 5;
    j[8][2] = 5;
    j
}

fn dfs(
    target: &[u8; 20],
    jump: &[[u8; 10]; 10],
    visited: &mut [bool; 10],
    path: &mut Vec<u8>,
    remaining: u8,
) -> bool {
    if remaining == 0 {
        let mut bytes = Vec::with_capacity(path.len());
        for &n in path.iter() {
            bytes.push(n - 1);
        }
        let h = sha1_pattern_bytes(&bytes);
        return &h == target;
    }

    // Guard clause: path should never be empty in normal flow
    let last = match path.last() {
        Some(&val) => val,
        None => return false,
    };
    for next in 1u8..=9 {
        if visited[next as usize] {
            continue;
        }
        let mid = jump[last as usize][next as usize];
        if mid != 0 && !visited[mid as usize] {
            continue;
        }
        visited[next as usize] = true;
        path.push(next);
        if dfs(target, jump, visited, path, remaining - 1) {
            return true;
        }
        path.pop();
        visited[next as usize] = false;
    }
    false
}

#[pyfunction]
pub fn recover_android_gesture(gesture_key_bytes: &[u8]) -> PyResult<String> {
    let target = parse_gesture_key_sha1(gesture_key_bytes)
        .ok_or_else(|| PyValueError::new_err("gesture_key_bytes is too short"))?;
    let jump = jump_table();

    for len in 4u8..=9 {
        for start in 1u8..=9 {
            let mut visited = [false; 10];
            visited[start as usize] = true;
            let mut path = vec![start];
            if dfs(&target, &jump, &mut visited, &mut path, len - 1) {
                let rendered = path
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join("-");
                return Ok(rendered);
            }
        }
    }

    Err(PyValueError::new_err("Gesture pattern not found"))
}

#[cfg(test)]
mod tests {
    use super::recover_android_gesture;
    use ring::digest;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_python() {
        INIT.call_once(|| {
            pyo3::Python::initialize();
        });
    }

    #[test]
    fn test_recover_known_pattern() {
        init_python();
        let pattern_bytes = [0u8, 1, 2, 3];
        let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &pattern_bytes);
        let out = recover_android_gesture(digest.as_ref()).unwrap();
        assert_eq!(out, "1-2-3-4");
    }

    #[test]
    fn test_recover_rejects_short() {
        init_python();
        let err = recover_android_gesture(&[1, 2, 3]).unwrap_err();
        assert!(format!("{err}").contains("too short"));
    }

    #[test]
    fn test_recover_long_pattern() {
        init_python();
        let pattern_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7, 8];
        let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &pattern_bytes);
        let out = recover_android_gesture(digest.as_ref()).unwrap();
        assert_eq!(out, "1-2-3-4-5-6-7-8-9");
    }
}
