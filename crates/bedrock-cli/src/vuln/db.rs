use crate::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub updated_at: String,
    pub entries_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub severity: crate::vuln::Severity,
    pub affected_purls: Vec<String>, // simplified for phase 2 stub
    pub fixed_version: Option<String>,
}

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
            if let Ok(advisories) = serde_json::from_str(&data) {
                self.advisories = advisories;
            }
        }
        Ok(())
    }

    pub fn update(&mut self) -> Result<SnapshotMeta> {
        // Phase 2 stub: In a real implementation this would fetch OSV zip files and parse them.
        // Here we just write a dummy snapshot.
        let dummy_advisories = vec![Advisory {
            id: "CVE-2023-12345".to_string(),
            aliases: vec![],
            severity: crate::vuln::Severity::High,
            affected_purls: vec!["pkg:deb/debian/bash".to_string()],
            fixed_version: Some("5.1-6".to_string()),
        }];

        let db_file = self.dir.join("snapshot.json");
        let data = serde_json::to_string_pretty(&dummy_advisories)?;
        fs::write(&db_file, data)?;

        self.advisories = dummy_advisories;

        Ok(SnapshotMeta {
            updated_at: chrono::Utc::now().to_rfc3339(),
            entries_count: self.advisories.len(),
        })
    }

    pub fn get_advisories(&self) -> &[Advisory] {
        &self.advisories
    }

    pub fn status(&self) -> Result<Option<SnapshotMeta>> {
        let db_file = self.dir.join("snapshot.json");
        if !db_file.exists() {
            return Ok(None);
        }

        // Return dummy meta for now based on file modification time
        if let Ok(meta) = std::fs::metadata(&db_file) {
            let updated_at = meta.modified().unwrap_or_else(|_| std::time::SystemTime::now());
            let dt: chrono::DateTime<chrono::Utc> = updated_at.into();
            return Ok(Some(SnapshotMeta {
                updated_at: dt.to_rfc3339(),
                entries_count: self.advisories.len(),
            }));
        }

        Ok(None)
    }
}





