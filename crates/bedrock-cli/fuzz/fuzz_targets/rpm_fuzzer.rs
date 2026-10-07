#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Same guarantee as the dpkg and apk fuzzers: a malformed rpm database
    // (Berkeley DB, NDB, or the header blobs inside either) must produce an
    // error, never a panic or an unbounded loop. Inputs starting with the
    // SQLite magic are skipped: those go through SQLite itself, which is
    // fuzzed upstream, and would make every iteration write a temp file.
    if data.starts_with(b"SQLite format 3\0") {
        return;
    }
    let _ = bedrock::sbom::rpm::parse_db(data, None, &Default::default());
});
