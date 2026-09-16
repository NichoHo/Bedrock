use flate2::read::GzDecoder;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub layer_digest: String,
    pub size: u64,
    pub mode: u32,
}

#[derive(Debug)]
pub struct FileInventory {
    pub files: HashMap<PathBuf, FileMetadata>,
}

#[derive(thiserror::Error, Debug)]
pub enum FsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("File not found in inventory: {0}")]
    FileNotFound(PathBuf),
    #[error("Failed to extract file: {0}")]
    ExtractFailed(String),
}

pub type Result<T> = std::result::Result<T, FsError>;

impl Default for FileInventory {
    fn default() -> Self {
        Self::new()
    }
}

impl FileInventory {
    pub fn new() -> Self {
        Self { files: HashMap::new() }
    }

    pub fn apply_layer(&mut self, tar_path: &Path, layer_digest: &str) -> Result<()> {
        let file = File::open(tar_path)?;

        let mut is_gz = false;
        let mut magic = [0u8; 2];
        let mut f_probe = File::open(tar_path)?;
        if f_probe.read_exact(&mut magic).is_ok() && magic == [0x1f, 0x8b] {
            is_gz = true;
        }

        if is_gz {
            let decoder = GzDecoder::new(file);
            let mut archive = Archive::new(decoder);
            self.process_entries(&mut archive, layer_digest)?;
        } else {
            let mut archive = Archive::new(file);
            self.process_entries(&mut archive, layer_digest)?;
        }

        Ok(())
    }

    fn process_entries<R: Read>(
        &mut self,
        archive: &mut Archive<R>,
        layer_digest: &str,
    ) -> Result<()> {
        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?.to_path_buf();
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            let parent = path.parent().unwrap_or_else(|| Path::new("")).to_path_buf();

            if file_name == ".wh..wh..opq" {
                self.files.retain(|p, _| !p.starts_with(&parent));
                continue;
            }

            if let Some(target_name) = file_name.strip_prefix(".wh.") {
                let target_path = parent.join(target_name);
                self.files.remove(&target_path);
                self.files.retain(|p, _| !p.starts_with(&target_path));
                continue;
            }

            self.files.insert(
                path,
                FileMetadata {
                    layer_digest: layer_digest.to_string(),
                    size: entry.header().size().unwrap_or(0),
                    mode: entry.header().mode().unwrap_or(0),
                },
            );
        }
        Ok(())
    }

    pub fn extract_file(&self, target_path: &Path, layer_tar_path: &Path) -> Result<Vec<u8>> {
        let file = File::open(layer_tar_path)?;

        let mut is_gz = false;
        let mut magic = [0u8; 2];
        let mut f_probe = File::open(layer_tar_path)?;
        if f_probe.read_exact(&mut magic).is_ok() && magic == [0x1f, 0x8b] {
            is_gz = true;
        }

        let extract = |archive: &mut Archive<&mut dyn Read>| -> Result<Option<Vec<u8>>> {
            let max_uncompressed = 1_000_000_000; // 1GB bomb limit
            let mut total_size = 0;

            for entry in archive.entries()? {
                let mut entry = entry?;
                let path = entry.path()?.to_path_buf();

                // Security: Reject escaping paths
                if path.is_absolute()
                    || path.components().any(|c| c == std::path::Component::ParentDir)
                {
                    return Err(FsError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Hostile tar entry",
                    )));
                }

                total_size += entry.size();
                if total_size > max_uncompressed {
                    return Err(FsError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Decompression bomb detected",
                    )));
                }

                if path == target_path {
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf)?;
                    return Ok(Some(buf));
                }
            }
            Ok(None)
        };

        let result = if is_gz {
            let mut decoder = GzDecoder::new(file);
            let mut archive = Archive::new(&mut decoder as &mut dyn Read);
            extract(&mut archive)
        } else {
            let mut file_read = file;
            let mut archive = Archive::new(&mut file_read as &mut dyn Read);
            extract(&mut archive)
        };

        match result? {
            Some(data) => Ok(data),
            None => Err(FsError::ExtractFailed(format!(
                "File {} not found in archive",
                target_path.display()
            ))),
        }
    }
}
