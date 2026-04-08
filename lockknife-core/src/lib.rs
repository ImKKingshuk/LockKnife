#![allow(clippy::useless_conversion)]

use pyo3::prelude::*;

mod binary;
mod bruteforce;
mod correlation;
mod crypto;
mod gesture;
mod network;
mod pattern;
mod sqlite_bulk;
mod yara_scan;
mod exploit;

#[pymodule]
fn lockknife_core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(binary::parse_dex_header_json, m)?)?;
    m.add_function(wrap_pyfunction!(binary::parse_elf_header_json, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::sha1_hex, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::sha256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::sha512_hex, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::md5_hex, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::aes256gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::aes256gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(bruteforce::bruteforce_numeric_pin, m)?)?;
    m.add_function(wrap_pyfunction!(bruteforce::dictionary_attack, m)?)?;
    m.add_function(wrap_pyfunction!(bruteforce::dictionary_attack_rules, m)?)?;
    m.add_function(wrap_pyfunction!(
        bruteforce::bruteforce_android_pin_sha1,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(gesture::recover_android_gesture, m)?)?;
    m.add_function(wrap_pyfunction!(pattern::scan_patterns_json, m)?)?;
    m.add_function(wrap_pyfunction!(sqlite_bulk::sqlite_table_to_json, m)?)?;
    m.add_function(wrap_pyfunction!(correlation::correlate_artifacts_json, m)?)?;
    m.add_function(wrap_pyfunction!(network::parse_ipv4_header_json, m)?)?;
    m.add_function(wrap_pyfunction!(yara_scan::yara_scan_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(yara_scan::yara_scan_file_rules, m)?)?;
    m.add_function(wrap_pyfunction!(run_tui, m)?)?;
    Ok(())
}

#[pyfunction]
fn run_tui(py: Python<'_>, callback: PyObject) -> PyResult<()> {
    lockknife_tui::run_tui(py, callback)
}
