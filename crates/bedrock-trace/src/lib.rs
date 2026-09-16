pub mod config;
pub mod sandbox;
pub mod tracer;
pub mod elf;
pub mod workload;

pub use config::{TraceConfig, WorkloadKind};
pub use sandbox::Sandbox;
pub use tracer::Tracer;
pub use elf::ElfClosure;

use std::collections::HashSet;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ReachSet {
    pub reached_paths: HashSet<PathBuf>,
    pub coverage_ratio: f64,
}

#[derive(thiserror::Error, Debug)]
pub enum TraceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Sandbox error: {0}")]
    Sandbox(String),
    #[error("Trace error: {0}")]
    Trace(String),
    #[error("ELF error: {0}")]
    Elf(String),
    #[error("Unsupported on this platform")]
    UnsupportedPlatform,
}

pub type Result<T> = std::result::Result<T, TraceError>;
