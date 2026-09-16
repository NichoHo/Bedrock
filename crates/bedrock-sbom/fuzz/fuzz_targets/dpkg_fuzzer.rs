#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // We only care that it doesn't panic on hostile/malformed dpkg status files
        let _ = bedrock_sbom::dpkg::parse_status(s);
    }
});
