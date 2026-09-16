pub mod apk;
pub mod cyclonedx;
pub mod dpkg;
pub mod node;
pub mod python;
pub mod rpm;
pub mod spdx;

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
    Fs(#[from] bedrock_fs::FsError),
    #[error("Parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, SbomError>;
