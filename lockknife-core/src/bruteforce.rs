use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use ring::digest;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::path::PathBuf;

fn pow10(len: u32) -> Option<u64> {
    let mut acc: u64 = 1;
    for _ in 0..len {
        acc = acc.checked_mul(10)?;
    }
    Some(acc)
}

const MAX_WORDLIST_BYTES: u64 = 20 * 1024 * 1024;

fn digest_for_algo(algo: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    match algo {
        "sha1" => Ok(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data)
            .as_ref()
            .to_vec()),
        "sha256" => Ok(digest::digest(&digest::SHA256, data).as_ref().to_vec()),
        "sha512" => Ok(digest::digest(&digest::SHA512, data).as_ref().to_vec()),
        _ => Err(format!("Unsupported algorithm: {algo}")),
    }
}

fn validate_wordlist(path: &str) -> PyResult<File> {
    let p = Path::new(path);
    if let Ok(root) = std::env::var("LOCKKNIFE_WORDLIST_ROOT") {
        let root = PathBuf::from(root);
        if let (Ok(abs), Ok(root_abs)) = (p.canonicalize(), root.canonicalize()) {
            if !abs.starts_with(&root_abs) {
                return Err(PyValueError::new_err("wordlist path outside allowed root"));
            }
        }
    }
    let meta = p
        .metadata()
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    if !meta.is_file() {
        return Err(PyValueError::new_err("wordlist must be a regular file"));
    }
    if meta.len() > MAX_WORDLIST_BYTES {
        return Err(PyValueError::new_err("wordlist exceeds size limit"));
    }
    File::open(p).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
pub fn bruteforce_numeric_pin(
    target_hash_hex: &str,
    algo: &str,
    length: u32,
) -> PyResult<Option<String>> {
    if length == 0 || length > 12 {
        return Err(PyValueError::new_err("length must be between 1 and 12"));
    }

    let target = hex::decode(target_hash_hex).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let max = pow10(length).ok_or_else(|| PyValueError::new_err("length too large"))?;
    let width = length as usize;

    let found = (0u64..max).into_par_iter().find_any(|candidate| {
        let pin = format!("{:0width$}", candidate, width = width);
        match digest_for_algo(algo, pin.as_bytes()) {
            Ok(d) => d == target,
            Err(_) => false,
        }
    });

    match found {
        None => Ok(None),
        Some(n) => Ok(Some(format!("{:0width$}", n, width = width))),
    }
}

#[pyfunction]
pub fn dictionary_attack(
    target_hash_hex: &str,
    algo: &str,
    wordlist_path: &str,
) -> PyResult<Option<String>> {
    let target = hex::decode(target_hash_hex).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let file = validate_wordlist(wordlist_path)?;
    let reader = BufReader::new(file);

    let found = reader.lines().par_bridge().find_any(|line| {
        let Ok(word) = line else { return false };
        let w = word.trim_end_matches(&['\r', '\n'][..]);
        if w.is_empty() {
            return false;
        }
        match digest_for_algo(algo, w.as_bytes()) {
            Ok(d) => d == target,
            Err(_) => false,
        }
    });

    match found {
        None => Ok(None),
        Some(Ok(line)) => Ok(Some(line.trim().to_string())),
        Some(Err(_)) => Ok(None),
    }
}

fn leetify(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a' | 'A' => '@',
            'e' | 'E' => '3',
            'i' | 'I' => '1',
            'o' | 'O' => '0',
            's' | 'S' => '$',
            't' | 'T' => '7',
            _ => c,
        })
        .collect()
}

fn capitalize(s: &str) -> String {
    let mut it = s.chars();
    let Some(first) = it.next() else {
        return String::new();
    };
    let mut out = String::new();
    out.extend(first.to_uppercase());
    out.push_str(&it.as_str().to_lowercase());
    out
}

fn variants(word: &str) -> Vec<String> {
    let w = word.trim();
    if w.is_empty() {
        return vec![];
    }
    let mut out = vec![
        w.to_string(),
        w.to_lowercase(),
        w.to_uppercase(),
        capitalize(w),
        leetify(w),
        leetify(&w.to_lowercase()),
    ];
    out.sort();
    out.dedup();
    out
}

#[pyfunction]
pub fn dictionary_attack_rules(
    target_hash_hex: &str,
    algo: &str,
    wordlist_path: &str,
    max_suffix: u32,
) -> PyResult<Option<String>> {
    let target = hex::decode(target_hash_hex).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let file = validate_wordlist(wordlist_path)?;
    let reader = BufReader::new(file);

    let found = reader.lines().par_bridge().find_map_any(|line| {
        let Ok(word) = line else { return None };
        let w = word.trim_end_matches(&['\r', '\n'][..]);
        if w.is_empty() {
            return None;
        }
        let vars = variants(w);
        for v in vars {
            if let Ok(d) = digest_for_algo(algo, v.as_bytes()) {
                if d == target {
                    return Some(v);
                }
            }
            for n in 0..=max_suffix {
                let cand = format!("{v}{n}");
                if let Ok(d) = digest_for_algo(algo, cand.as_bytes()) {
                    if d == target {
                        return Some(cand);
                    }
                }
            }
        }
        None
    });

    Ok(found)
}

fn android_password_to_hash_input(salt: i64, secret: &str) -> Vec<u8> {
    format!("{salt}{secret}").into_bytes()
}

#[pyfunction]
pub fn bruteforce_android_pin_sha1(
    target_sha1_hex: &str,
    salt: i64,
    length: u32,
) -> PyResult<Option<String>> {
    if length == 0 || length > 12 {
        return Err(PyValueError::new_err("length must be between 1 and 12"));
    }
    let target = hex::decode(target_sha1_hex).map_err(|e| PyValueError::new_err(e.to_string()))?;
    if target.len() != 20 {
        return Err(PyValueError::new_err(
            "target_sha1_hex must be 20 bytes (40 hex chars)",
        ));
    }
    let max = pow10(length).ok_or_else(|| PyValueError::new_err("length too large"))?;
    let width = length as usize;

    let found = (0u64..max).into_par_iter().find_any(|candidate| {
        let pin = format!("{:0width$}", candidate, width = width);
        let input = android_password_to_hash_input(salt, &pin);
        let d = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
        d.as_ref() == target.as_slice()
    });

    match found {
        None => Ok(None),
        Some(n) => Ok(Some(format!("{:0width$}", n, width = width))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bruteforce_android_pin_sha1, bruteforce_numeric_pin, dictionary_attack,
        dictionary_attack_rules,
    };
    use ring::digest;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Once;

    fn temp_wordlist(contents: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "lockknife_wordlist_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(unique);
        fs::write(&path, contents).unwrap();
        path
    }

    static INIT: Once = Once::new();

    fn init_python() {
        INIT.call_once(|| {
            pyo3::Python::initialize();
        });
    }

    #[test]
    fn test_bruteforce_numeric_pin_finds_match() {
        init_python();
        let pin = "1234";
        let digest = digest::digest(&digest::SHA256, pin.as_bytes());
        let out = bruteforce_numeric_pin(&hex::encode(digest.as_ref()), "sha256", 4).unwrap();
        assert_eq!(out, Some(pin.to_string()));
    }

    #[test]
    fn test_dictionary_attack_finds_word() {
        init_python();
        let word = "secret";
        let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, word.as_bytes());
        let path = temp_wordlist("alpha\nsecret\nbeta\n");
        let out = dictionary_attack(
            &hex::encode(digest.as_ref()),
            "sha1",
            path.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(out, Some(word.to_string()));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_dictionary_attack_rules_suffix() {
        init_python();
        let word = "pass2";
        let digest = digest::digest(&digest::SHA256, word.as_bytes());
        let path = temp_wordlist("pass\n");
        let out = dictionary_attack_rules(
            &hex::encode(digest.as_ref()),
            "sha256",
            path.to_str().unwrap(),
            3,
        )
        .unwrap();
        assert_eq!(out, Some(word.to_string()));
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_bruteforce_android_pin_sha1() {
        init_python();
        let pin = "1234";
        let salt = 123;
        let input = format!("{salt}{pin}");
        let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, input.as_bytes());
        let out = bruteforce_android_pin_sha1(&hex::encode(digest.as_ref()), salt, 4).unwrap();
        assert_eq!(out, Some(pin.to_string()));
    }

    #[test]
    fn test_bruteforce_invalid_length() {
        init_python();
        let err = bruteforce_numeric_pin("00", "sha1", 0).unwrap_err();
        assert!(format!("{err}").contains("length"));
    }

    #[test]
    fn test_bruteforce_length_bounds() {
        init_python();
        let digest = digest::digest(&digest::SHA256, b"000000000000");
        let out = bruteforce_numeric_pin(&hex::encode(digest.as_ref()), "sha256", 12).unwrap();
        assert_eq!(out, Some("000000000000".to_string()));

        let err = bruteforce_numeric_pin("00", "sha1", 13).unwrap_err();
        assert!(format!("{err}").contains("length"));
    }
}
