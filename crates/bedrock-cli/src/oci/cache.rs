use crate::Result;
use std::fs;
use std::path::PathBuf;

#[derive(Clone)]
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
            return Err(anyhow::anyhow!(crate::oci::OciError::InvalidDigest(
                "Invalid digest format".into()
            )));
        }
        Ok(self.blobs_dir.join("sha256").join(digest_clean))
    }

    pub fn blob_exists(&self, digest: &str) -> bool {
        match self.get_blob_path(digest) {
            Ok(path) => fs::metadata(&path).is_ok(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_digest() {
        let cache = Cache { blobs_dir: PathBuf::from("/tmp/bedrock-test") };
        assert!(cache.get_blob_path("not-a-digest").is_err());
        assert!(cache.get_blob_path("sha256:tooshort").is_err());
        assert!(cache.get_blob_path(&format!("sha256:{}", "g".repeat(64))).is_err());
    }

    #[test]
    fn accepts_valid_digest_with_or_without_prefix() {
        let cache = Cache { blobs_dir: PathBuf::from("/tmp/bedrock-test") };
        let hex64 = "a".repeat(64);
        assert!(cache.get_blob_path(&hex64).is_ok());
        assert!(cache.get_blob_path(&format!("sha256:{hex64}")).is_ok());
    }
}
