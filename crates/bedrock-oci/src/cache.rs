use crate::Result;
use std::path::PathBuf;
use tokio::fs;

pub struct Cache {
    blobs_dir: PathBuf,
}

impl Cache {
    pub async fn new() -> Result<Self> {
        let cache_home = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
        let blobs_dir = cache_home.join("bedrock").join("blobs");
        fs::create_dir_all(&blobs_dir).await?;
        Ok(Self { blobs_dir })
    }

    pub fn get_blob_path(&self, digest: &str) -> PathBuf {
        let digest_clean = digest.strip_prefix("sha256:").unwrap_or(digest);
        self.blobs_dir.join("sha256").join(digest_clean)
    }

    pub async fn blob_exists(&self, digest: &str) -> bool {
        fs::metadata(self.get_blob_path(digest)).await.is_ok()
    }

    pub async fn write_blob(&self, digest: &str, data: &[u8]) -> Result<()> {
        let path = self.get_blob_path(digest);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&path, data).await?;
        Ok(())
    }
}
