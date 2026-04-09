#![no_main]

use libfuzzer_sys::fuzz_target;
use lockknife_core::correlation;

fuzz_target!(|data: &[u8]| {
    // Test correlate_artifacts_json with fuzzed JSON input
    // The function should handle invalid JSON gracefully without panicking
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = correlation::correlate_artifacts_json(s);
    }
});
