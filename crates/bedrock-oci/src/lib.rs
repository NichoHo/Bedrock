pub mod cache;
pub mod manifest;
pub mod reference;
pub mod registry;
pub mod layout;

pub use cache::Cache;
pub use manifest::{Manifest, Descriptor};
pub use reference::ImageReference;
pub use registry::RegistryClient;
pub use layout::OciLayout;

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
    #[error("Unsupported media type: {0}")]
    UnsupportedMediaType(String),
}

pub type Result<T> = std::result::Result<T, OciError>;
