use crate::sbom::Package;
use anyhow::Result;
use std::path::PathBuf;

pub fn parse_rpm<F>(_inventory: &crate::fs::FileInventory, _resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    // Phase 1 TODO: rpm parser (SQLite/BDB)
    Ok(Vec::new())
}
