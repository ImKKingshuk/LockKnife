use once_cell::sync::Lazy;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::Regex;
use std::str::FromStr;

static RE_SHA256: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap());
static RE_URL: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bhttps?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+").unwrap());
static RE_IPV4: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static RE_DOMAIN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b").unwrap());

#[derive(serde::Serialize)]
struct IocMatchItem {
    ioc: String,
    kind: String,
}

fn detect_iocs_native_inner(data_str: &str) -> Vec<IocMatchItem> {
    let mut matches = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // 1. SHA256
    for mat in RE_SHA256.find_iter(data_str) {
        let ioc = mat.as_str().to_lowercase();
        let key = (String::from("sha256"), ioc.clone());
        if !seen.contains(&key) {
            seen.insert(key);
            matches.push(IocMatchItem {
                ioc,
                kind: String::from("sha256"),
            });
        }
    }

    // 2. URL
    for mat in RE_URL.find_iter(data_str) {
        let ioc = mat.as_str().to_string();
        let key = (String::from("url"), ioc.clone());
        if !seen.contains(&key) {
            seen.insert(key);
            matches.push(IocMatchItem {
                ioc,
                kind: String::from("url"),
            });
        }
    }

    // 3. IPv4
    for mat in RE_IPV4.find_iter(data_str) {
        let candidate = mat.as_str().to_string();
        if std::net::Ipv4Addr::from_str(&candidate).is_ok() {
            let key = (String::from("ipv4"), candidate.clone());
            if !seen.contains(&key) {
                seen.insert(key);
                matches.push(IocMatchItem {
                    ioc: candidate,
                    kind: String::from("ipv4"),
                });
            }
        }
    }

    // 4. Domain
    for mat in RE_DOMAIN.find_iter(data_str) {
        let candidate = mat.as_str().to_lowercase().trim_matches('.').to_string();
        if candidate.starts_with("http") {
            continue;
        }
        let key = (String::from("domain"), candidate.clone());
        if !seen.contains(&key) {
            seen.insert(key);
            matches.push(IocMatchItem {
                ioc: candidate,
                kind: String::from("domain"),
            });
        }
    }

    matches
}

/// A highly optimized Rust-native regex matching engine for high-speed network/IOC indicators.
/// Releases the GIL via `py.allow_threads`.
#[pyfunction]
pub fn detect_iocs_native(py: Python<'_>, data: &[u8]) -> PyResult<String> {
    let data_vec = data.to_vec();
    py.detach(move || {
        let data_str = String::from_utf8_lossy(&data_vec);
        let matches = detect_iocs_native_inner(&data_str);
        serde_json::to_string(&matches)
            .map_err(|e| PyValueError::new_err(format!("serialization failed: {e}")))
    })
}

#[cfg(test)]
mod tests {
    use super::detect_iocs_native_inner;

    #[test]
    fn test_detect_iocs_native_sha256() {
        let text = "Here is a hash: E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 and another one.";
        let res = detect_iocs_native_inner(text);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].kind, "sha256");
        assert_eq!(res[0].ioc, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_detect_iocs_native_url() {
        let text = "Check out https://google.com/path?query=1 and http://127.0.0.1:8080/foo.";
        let res = detect_iocs_native_inner(text);
        assert!(res.iter().any(|item| item.kind == "url" && item.ioc == "https://google.com/path?query=1"));
        assert!(res.iter().any(|item| item.kind == "url" && item.ioc == "http://127.0.0.1:8080/foo."));
    }

    #[test]
    fn test_detect_iocs_native_ipv4() {
        let text = "Connect to 192.168.1.1 or 8.8.8.8, but ignore 300.400.500.600.";
        let res = detect_iocs_native_inner(text);
        let ips: Vec<&str> = res.iter().filter(|item| item.kind == "ipv4").map(|item| item.ioc.as_str()).collect();
        assert!(ips.contains(&"192.168.1.1"));
        assert!(ips.contains(&"8.8.8.8"));
        assert!(!ips.contains(&"300.400.500.600"));
    }

    #[test]
    fn test_detect_iocs_native_domain() {
        let text = "Visits to google.com, test-domain.co.uk, and .stripme.org. but http.exclude.me.";
        let res = detect_iocs_native_inner(text);
        let domains: Vec<&str> = res.iter().filter(|item| item.kind == "domain").map(|item| item.ioc.as_str()).collect();
        assert!(domains.contains(&"google.com"));
        assert!(domains.contains(&"test-domain.co.uk"));
        assert!(domains.contains(&"stripme.org"));
        assert!(!domains.contains(&"http.exclude.me"));
    }
}
