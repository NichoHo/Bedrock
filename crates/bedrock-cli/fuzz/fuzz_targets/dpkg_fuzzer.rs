#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // We only care that a hostile/malformed dpkg status file produces an
        // error or an empty result, never a panic or unbounded memory use.
        let _ = bedrock::sbom::dpkg::parse_status(s, "debian", None);
    }
});
