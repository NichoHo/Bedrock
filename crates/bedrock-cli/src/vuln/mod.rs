pub mod db;
pub mod scanner;

pub use db::VulnerabilityDb;
pub use scanner::{Finding, Scanner, Severity};

#[derive(thiserror::Error, Debug)]
pub enum VulnError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Database error: {0}")]
    Database(String),
}

pub type Result<T> = std::result::Result<T, VulnError>;





