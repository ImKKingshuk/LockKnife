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
    
    // Exploitation functions
    m.add_function(wrap_pyfunction!(exploit::craft_wifi_beacon, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::craft_wifi_probe_request, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::craft_wifi_deauth, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::craft_wifi_auth, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::craft_wifi_association, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::craft_bluetooth_lmp, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::parse_wifi_frame, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::validate_wifi_checksum, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::bruteforce_wps_pin_checksum, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::bruteforce_wps_pin_parallel, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::wps_pixie_dust_accelerated, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::generate_wps_pins, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::bruteforce_wps_pin_with_checksum, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::pbkdf2_sha1, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::pbkdf2_sha1_parallel, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::hmac_sha1_vector, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::derive_psk, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::validate_handshake, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::crack_handshake, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::crack_handshake_parallel, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::scan_ports_parallel, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::scan_port_range, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::scan_common_ports, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::scan_service_banner, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::ping_sweep_parallel, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::tcp_syn_scan, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::udp_scan, m)?)?;
    m.add_function(wrap_pyfunction!(exploit::scan_top_ports, m)?)?;
    
    m.add_function(wrap_pyfunction!(run_tui, m)?)?;
    Ok(())
}

#[pyfunction]
fn run_tui(py: Python<'_>, callback: PyObject) -> PyResult<()> {
    lockknife_tui::run_tui(py, callback)
}
