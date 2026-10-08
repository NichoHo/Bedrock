//! Bedrock's implementation, as a library, so it can be exercised outside the
//! CLI binary: by tests (see `tests/`) and by fuzz targets (see `fuzz/`),
//! which need a library crate to link against rather than the `bedrock`
//! binary itself.
pub use anyhow::Result;

pub mod fs;
pub mod oci;
pub mod report;
pub mod sbom;
pub mod trace;
pub mod vuln;

/// Makes text from inside an image safe to print: control characters (ESC,
/// newlines, ...) become visible `\u{..}` escapes, so a crafted filename can't
/// inject terminal escape sequences or forge output lines.
pub fn escape_control(s: &str) -> String {
    s.chars()
        .flat_map(|c| if c.is_control() { c.escape_default().collect() } else { vec![c] })
        .collect()
}
