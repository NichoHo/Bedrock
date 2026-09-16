use std::path::{Path, PathBuf};
use crate::{Package, Result};

pub fn parse_rpm<F>(
    _inventory: &bedrock_fs::FileInventory,
    _resolver: F,
) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    // Phase 1 TODO: rpm parser (SQLite/BDB)
    Ok(Vec::new())
}
