pub mod apk;
pub mod cyclonedx;
pub mod dpkg;
pub mod node;
pub mod python;
pub mod spdx;
// rpm (dpkg/apk-family rpm package DB) is not implemented yet; see BEDROCK_SPEC.md Phase 1.

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub purl: String,
    pub files: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Sbom {
    pub packages: Vec<Package>,
}

#[derive(thiserror::Error, Debug)]
pub enum SbomError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("FS error: {0}")]
    Fs(#[from] crate::fs::FsError),
    #[error("Parse error: {0}")]
    Parse(String),
}

/// A unique-enough identifier for one SBOM document: SPDX's `documentNamespace`
/// and CycloneDX's `serialNumber` both require a value that doesn't repeat
/// across documents. Built from a hash of the process id and current time
/// rather than pulling in a `uuid` crate for one call site.
pub fn document_id() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.update(nanos.to_le_bytes());
    let hash = hasher.finalize();
    let hex = hex::encode(hash);
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}
