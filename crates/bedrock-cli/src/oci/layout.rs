use crate::oci::{Manifest, OciError}; use anyhow::Result;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::fs;

#[derive(Debug, Deserialize)]
struct OciIndex {
    manifests: Vec<crate::oci::manifest::Descriptor>,
}

pub struct OciLayout {
    path: PathBuf,
}

impl OciLayout {
    pub fn new(path: &Path) -> Self {
        Self { path: path.to_path_buf() }
    }

    pub fn read_index(&self) -> Result<Vec<crate::oci::manifest::Descriptor>> {
        let index_path = self.path.join("index.json");
        let data = fs::read_to_string(&index_path).map_err(OciError::Io)?;
        let index: OciIndex = serde_json::from_str(&data)?;
        Ok(index.manifests)
    }

    pub fn read_manifest(&self, digest: &str) -> Result<Manifest> {
        let manifest_path = self.get_blob_path(digest)?;

        // Try reading it. For our dummy layouts, it might not exist or be empty.
        match fs::read_to_string(&manifest_path) {
            Ok(data) => {
                let manifest: Manifest = serde_json::from_str(&data)?;
                Ok(manifest)
            }
            Err(_) => {
                // If it fails, maybe return a dummy for now since we just created dummy layouts.
                // But in a real scenario we error out.
                Err(OciError::ManifestNotFound.into())
            }
        }
    }

    pub fn get_blob_path(&self, digest: &str) -> Result<PathBuf> {
        let digest_clean = digest.strip_prefix("sha256:").unwrap_or(digest);
        if digest_clean.len() != 64 || !digest_clean.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow::anyhow!(crate::oci::OciError::InvalidDigest("Invalid digest format".into())));
        }
        Ok(self.path.join("blobs").join("sha256").join(digest_clean))
    }
}







