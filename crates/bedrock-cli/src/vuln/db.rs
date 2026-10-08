//! On-disk advisory snapshot: one JSON file per source plus a `manifest.json`
//! naming each file's SHA-256. The manifest is written last and files are
//! content-addressed by name, so an interrupted update leaves the previous
//! snapshot intact, and a truncated or edited file fails verification instead
//! of silently scanning against half a database (BEDROCK_SPEC.md 9.5).
use super::advisory::Advisory;
use crate::Result;
use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const SCHEMA: u32 = 1;
const MANIFEST: &str = "manifest.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub updated_at: String,
    /// SHA-256 over every file's name and digest: the snapshot's identity,
    /// recorded in reports because CVE counts change daily.
    pub digest: String,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    /// Logical source name, e.g. `osv-PyPI`, `debian`.
    pub source: String,
    /// On-disk name: `<source>-<sha256 prefix>.json`.
    pub file: String,
    pub sha256: String,
    pub bytes: u64,
    pub advisories: usize,
}

impl Manifest {
    pub fn advisories(&self) -> usize {
        self.files.iter().map(|f| f.advisories).sum()
    }

    pub fn age_days(&self) -> Option<i64> {
        let t = chrono::DateTime::parse_from_rfc3339(&self.updated_at).ok()?;
        Some((chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_days())
    }
}

pub struct VulnerabilityDb {
    dir: PathBuf,
}

impl VulnerabilityDb {
    /// `BEDROCK_DB_DIR` overrides the default cache location.
    pub fn new() -> Result<Self> {
        if let Some(dir) = std::env::var_os("BEDROCK_DB_DIR") {
            return Self::at(dir.into());
        }
        let cache_home = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
        Self::at(cache_home.join("bedrock").join("vuln-db"))
    }

    pub fn at(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// `None` when no snapshot has been fetched yet.
    pub fn manifest(&self) -> Result<Option<Manifest>> {
        let path = self.dir.join(MANIFEST);
        if !path.exists() {
            return Ok(None);
        }
        let m: Manifest = serde_json::from_slice(&fs::read(&path)?)
            .with_context(|| format!("corrupt {}; run `bedrock db update`", path.display()))?;
        if m.schema != SCHEMA {
            bail!(
                "snapshot schema {} is not supported (expected {SCHEMA}); run `bedrock db update`",
                m.schema
            );
        }
        Ok(Some(m))
    }

    /// Replaces the snapshot with `sources` (source name, advisories).
    pub fn replace(&self, sources: Vec<(String, Vec<Advisory>)>) -> Result<Manifest> {
        let mut files = Vec::new();
        for (source, advisories) in sources {
            let data = serde_json::to_vec(&advisories)?;
            let sha256 = hex::encode(Sha256::digest(&data));
            let file = format!("{source}-{}.json", &sha256[..12]);
            fs::write(self.dir.join(&file), &data)?;
            files.push(FileEntry {
                source,
                file,
                sha256,
                bytes: data.len() as u64,
                advisories: advisories.len(),
            });
        }
        files.sort_by(|a, b| a.source.cmp(&b.source));
        let mut h = Sha256::new();
        for f in &files {
            h.update(format!("{}:{}\n", f.source, f.sha256));
        }
        let manifest = Manifest {
            schema: SCHEMA,
            updated_at: chrono::Utc::now().to_rfc3339(),
            digest: hex::encode(h.finalize()),
            files,
        };
        let tmp = self.dir.join("manifest.json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&manifest)?)?;
        fs::rename(&tmp, self.dir.join(MANIFEST))?;
        self.remove_unlisted(&manifest);
        Ok(manifest)
    }

    /// Best effort: a leftover file wastes disk but is never read.
    fn remove_unlisted(&self, m: &Manifest) {
        let Ok(rd) = fs::read_dir(&self.dir) else { return };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".json")
                && name != MANIFEST
                && !m.files.iter().any(|f| f.file == name)
            {
                let _ = fs::remove_file(e.path());
            }
        }
    }

    /// Reads the advisories of every source `wanted` accepts, refusing on any
    /// missing, truncated or modified file. This is the only way `scan` should
    /// read the snapshot.
    pub fn load_sources(&self, wanted: impl Fn(&str) -> bool) -> Result<Vec<Advisory>> {
        let Some(m) = self.manifest()? else {
            bail!("no advisory snapshot; run `bedrock db update`");
        };
        let mut all = Vec::new();
        for f in m.files.iter().filter(|f| wanted(&f.source)) {
            all.extend(read_verified(&self.dir, f)?);
        }
        Ok(all)
    }
}

fn read_verified(dir: &Path, f: &FileEntry) -> Result<Vec<Advisory>> {
    let data = fs::read(dir.join(&f.file))
        .with_context(|| format!("snapshot file {} is missing; run `bedrock db update`", f.file))?;
    if data.len() as u64 != f.bytes || hex::encode(Sha256::digest(&data)) != f.sha256 {
        bail!("snapshot file {} fails its digest check (truncated or modified); run `bedrock db update`", f.file);
    }
    Ok(serde_json::from_slice(&data)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adv(id: &str) -> Advisory {
        Advisory { id: id.into(), aliases: vec![], severity: None, cvss: None, affected: vec![] }
    }

    #[test]
    fn roundtrip_and_supersede() {
        let t = tempfile::tempdir().unwrap();
        let db = VulnerabilityDb::at(t.path().into()).unwrap();
        assert!(db.manifest().unwrap().is_none());
        db.replace(vec![("a".into(), vec![adv("X-1")]), ("b".into(), vec![adv("X-2")])]).unwrap();
        assert_eq!(db.load_sources(|_| true).unwrap().len(), 2);
        let m = db.replace(vec![("a".into(), vec![adv("X-3")])]).unwrap();
        assert_eq!(m.advisories(), 1);
        // old b-*.json and old a-*.json were swept
        let jsons = fs::read_dir(t.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
            .count();
        assert_eq!(jsons, 2); // manifest + one data file
    }

    #[test]
    fn truncated_file_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let db = VulnerabilityDb::at(t.path().into()).unwrap();
        let m = db.replace(vec![("a".into(), vec![adv("X-1"), adv("X-2")])]).unwrap();
        let p = t.path().join(&m.files[0].file);
        let d = fs::read(&p).unwrap();
        fs::write(&p, &d[..d.len() / 2]).unwrap();
        let err = db.load_sources(|_| true).unwrap_err().to_string();
        assert!(err.contains("digest check"), "{err}");
    }
}
