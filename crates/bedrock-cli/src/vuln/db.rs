use crate::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub updated_at: String,
    pub entries_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub severity: Severity,
    pub affected_purls: Vec<String>,
    pub fixed_version: Option<String>,
}

/// A local snapshot of vulnerability advisories. `bedrock db update` (not yet
/// implemented; see BEDROCK_SPEC.md Phase 2) is meant to populate this from OSV
/// plus distro feeds. Until then this only reports whatever snapshot, if any,
/// already exists on disk.
pub struct VulnerabilityDb {
    dir: PathBuf,
    advisories: Vec<Advisory>,
}

impl VulnerabilityDb {
    pub fn new() -> Result<Self> {
        let cache_home = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
        let db_dir = cache_home.join("bedrock").join("vuln-db");
        fs::create_dir_all(&db_dir)?;

        let mut db = Self { dir: db_dir, advisories: Vec::new() };
        db.load_snapshot()?;
        Ok(db)
    }

    pub fn load_snapshot(&mut self) -> Result<()> {
        let db_file = self.dir.join("snapshot.json");
        if db_file.exists() {
            let data = fs::read_to_string(&db_file)?;
            self.advisories = serde_json::from_str(&data)?;
        }
        Ok(())
    }

    pub fn status(&self) -> Result<Option<SnapshotMeta>> {
        let db_file = self.dir.join("snapshot.json");
        if !db_file.exists() {
            return Ok(None);
        }

        let meta = std::fs::metadata(&db_file)?;
        let updated_at = meta.modified().unwrap_or_else(|_| std::time::SystemTime::now());
        let dt: chrono::DateTime<chrono::Utc> = updated_at.into();
        Ok(Some(SnapshotMeta { updated_at: dt.to_rfc3339(), entries_count: self.advisories.len() }))
    }
}
