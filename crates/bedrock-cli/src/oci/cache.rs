use crate::Result;
use std::path::PathBuf;
use std::fs;

pub struct Cache {
    blobs_dir: PathBuf,
}

impl Cache {
    pub fn new() -> Result<Self> {
        let cache_home = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
        let blobs_dir = cache_home.join("bedrock").join("blobs");
        fs::create_dir_all(&blobs_dir)?;
        Ok(Self { blobs_dir })
    }

    pub fn get_blob_path(&self, digest: &str) -> Result<PathBuf> {
        let digest_clean = digest.strip_prefix("sha256:").unwrap_or(digest);
        if digest_clean.len() != 64 || !digest_clean.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow::anyhow!(crate::oci::OciError::InvalidDigest("Invalid digest format".into())));
        }
        Ok(self.blobs_dir.join("sha256").join(digest_clean))
    }

    pub fn blob_exists(&self, digest: &str) -> bool {
        if let Ok(path) = self.get_blob_path(digest) {
            fs::metadata(&path).is_ok()
        } else {
            false
        }
    }

    pub fn write_blob(&self, digest: &str, data: &[u8]) -> Result<()> {
        let path = self.get_blob_path(digest)?;
        
        let digest_clean = digest.strip_prefix("sha256:").unwrap_or(digest);
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());
        if hash != digest_clean {
            return Err(anyhow::anyhow!(crate::oci::OciError::InvalidDigest(format!("Digest mismatch: expected {}, got {}", digest_clean, hash))));
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, data)?;
        Ok(())
    }
}







