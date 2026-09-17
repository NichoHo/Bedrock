use crate::oci::manifest::resolve_manifest;
use crate::oci::{Manifest, OciError};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub struct OciLayout {
    path: PathBuf,
}

impl OciLayout {
    pub fn new(path: &Path) -> Self {
        Self { path: path.to_path_buf() }
    }

    /// True only for a directory that actually looks like an OCI image layout
    /// (has an `oci-layout` marker file), so an arbitrary directory that
    /// happens to share a name with a registry image isn't misread as one.
    pub fn looks_like_layout(path: &Path) -> bool {
        path.join("oci-layout").is_file()
    }

    pub fn get_blob_path(&self, digest: &str) -> Result<PathBuf> {
        let digest_clean = digest.strip_prefix("sha256:").unwrap_or(digest);
        if digest_clean.len() != 64 || !digest_clean.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow::anyhow!(crate::oci::OciError::InvalidDigest(
                "Invalid digest format".into()
            )));
        }
        Ok(self.path.join("blobs").join("sha256").join(digest_clean))
    }

    fn read_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let path = self.get_blob_path(digest)?;
        fs::read(&path).map_err(|e| OciError::Io(e).into())
    }

    /// Reads `index.json` and resolves it (following one level of nested index,
    /// if present) down to the manifest for the requested platform.
    pub fn resolve_manifest(&self, os: &str, arch: &str) -> Result<Manifest> {
        let index_path = self.path.join("index.json");
        let index_data =
            fs::read(&index_path).with_context(|| format!("reading {}", index_path.display()))?;
        resolve_manifest(&index_data, os, arch, |digest| self.read_blob(digest))
            .context("failed to resolve a manifest from index.json")
    }
}
