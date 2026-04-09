#![no_main]

use libfuzzer_sys::fuzz_target;
use lockknife_core::binary;

fuzz_target!(|data: &[u8]| {
    // Test parse_dex_header_json with fuzzed input
    // The function should handle invalid inputs gracefully without panicking
    let _ = binary::parse_dex_header_json(data);
});
