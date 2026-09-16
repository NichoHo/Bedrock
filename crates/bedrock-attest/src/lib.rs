pub mod in_toto;
pub mod slsa;
pub mod sigstore;

use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum AttestError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Signing error: {0}")]
    Signing(String),
}

pub type Result<T> = std::result::Result<T, AttestError>;
