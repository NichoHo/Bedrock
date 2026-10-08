#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Same guarantee as dpkg_fuzzer: malformed apk db input must error or
        // return an empty result, never panic.
        let _ = bedrock::sbom::apk::parse_status(s, "alpine", None);
    }
});
