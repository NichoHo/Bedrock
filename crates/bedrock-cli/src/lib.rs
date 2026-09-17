//! Bedrock's implementation, as a library, so it can be exercised outside the
//! CLI binary: by tests (see `tests/`) and by fuzz targets (see `fuzz/`),
//! which need a library crate to link against rather than the `bedrock`
//! binary itself.
pub use anyhow::Result;

pub mod fs;
pub mod oci;
pub mod sbom;
pub mod vuln;
