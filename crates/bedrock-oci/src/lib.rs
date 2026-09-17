pub mod cache;
pub mod layout;
pub mod manifest;
pub mod reference;
pub mod registry;

pub use cache::Cache;
pub use layout::OciLayout;
pub use manifest::{Descriptor, Manifest};
pub use reference::ImageReference;
pub use registry::RegistryClient;

#[derive(thiserror::Error, Debug)]
pub enum OciError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid image reference: {0}")]
    InvalidReference(String),
    #[error("Blob not found: {0}")]
    BlobNotFound(String),
    #[error("Manifest not found")]
    ManifestNotFound,
    #[error("Invalid digest: {0}")]
    InvalidDigest(String),
    #[error("Unsupported media type: {0}")]
    UnsupportedMediaType(String),
}

pub type Result<T> = std::result::Result<T, OciError>;
