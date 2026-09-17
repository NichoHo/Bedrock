use flate2::read::GzDecoder;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink(PathBuf),
    HardLink(PathBuf),
    Other,
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub layer_digest: String,
    pub size: u64,
    pub mode: u32,
    pub kind: EntryKind,
}

#[derive(Debug, Default)]
pub struct FileInventory {
    pub files: HashMap<PathBuf, FileMetadata>,
}

#[derive(thiserror::Error, Debug)]
pub enum FsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to extract file: {0}")]
    ExtractFailed(String),
    #[error("Hostile tar entry: {0}")]
    HostileEntry(PathBuf),
    #[error("Decompression bomb detected (uncompressed size exceeds {0} bytes)")]
    DecompressionBomb(u64),
}

pub type Result<T> = std::result::Result<T, FsError>;

/// Maximum bytes a single layer may expand to while being walked or extracted.
const MAX_UNCOMPRESSED_BYTES: u64 = 1_000_000_000;

/// Rejects absolute paths and any path containing a `..` component. Untrusted
/// tar entries must be rejected outright rather than silently rewritten:
/// normalizing `../../etc/passwd` down to `etc/passwd` would make a hostile
/// entry look legitimate instead of refusing it.
fn reject_hostile_path(path: &Path) -> Result<()> {
    if path.is_absolute() || path.components().any(|c| c == std::path::Component::ParentDir) {
        return Err(FsError::HostileEntry(path.to_path_buf()));
    }
    Ok(())
}

/// Strips a leading `./` (or repeated `./`) so `./var/lib/dpkg/status` and
/// `var/lib/dpkg/status` land on the same inventory key. Callers must run
/// [`reject_hostile_path`] first; this does not defend against `..` or
/// absolute paths.
fn strip_leading_curdir(path: &Path) -> PathBuf {
    path.components().skip_while(|c| *c == std::path::Component::CurDir).collect()
}

/// Opens `tar_path` as a tar stream, transparently gunzipping if the file
/// starts with the gzip magic bytes.
fn open_archive(tar_path: &Path) -> Result<Archive<Box<dyn Read>>> {
    let mut probe = File::open(tar_path)?;
    let mut magic = [0u8; 2];
    let is_gz = probe.read_exact(&mut magic).is_ok() && magic == [0x1f, 0x8b];

    let file = File::open(tar_path)?;
    let reader: Box<dyn Read> = if is_gz { Box::new(GzDecoder::new(file)) } else { Box::new(file) };
    Ok(Archive::new(reader))
}

impl FileInventory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_layer(&mut self, tar_path: &Path, layer_digest: &str) -> Result<()> {
        let mut archive = open_archive(tar_path)?;
        let mut total_size: u64 = 0;

        for entry in archive.entries()? {
            let entry = entry?;
            let raw_path = entry.path()?;
            reject_hostile_path(&raw_path)?;
            let path = strip_leading_curdir(&raw_path);

            total_size += entry.size();
            if total_size > MAX_UNCOMPRESSED_BYTES {
                return Err(FsError::DecompressionBomb(MAX_UNCOMPRESSED_BYTES));
            }

            let file_name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let parent = path.parent().unwrap_or_else(|| Path::new("")).to_path_buf();

            if file_name == ".wh..wh..opq" {
                // Opaque whiteout: everything already recorded under this directory
                // from an earlier (lower) layer is hidden, unless this same layer
                // also re-added it.
                self.files.retain(|p, meta| {
                    if p.starts_with(&parent) && p != &parent {
                        meta.layer_digest == layer_digest
                    } else {
                        true
                    }
                });
                continue;
            }

            if let Some(target_name) = file_name.strip_prefix(".wh.") {
                if !target_name.is_empty() {
                    let target_path = parent.join(target_name);
                    self.files.retain(|p, _| !p.starts_with(&target_path));
                }
                continue;
            }

            let kind = match entry.header().entry_type() {
                tar::EntryType::Directory => EntryKind::Directory,
                tar::EntryType::Symlink => EntryKind::Symlink(
                    entry.link_name()?.map(|l| l.to_path_buf()).unwrap_or_default(),
                ),
                tar::EntryType::Link => EntryKind::HardLink(
                    entry.link_name()?.map(|l| l.to_path_buf()).unwrap_or_default(),
                ),
                tar::EntryType::Regular => EntryKind::File,
                _ => EntryKind::Other,
            };

            self.files.insert(
                path,
                FileMetadata {
                    layer_digest: layer_digest.to_string(),
                    size: entry.header().size().unwrap_or(0),
                    mode: entry.header().mode().unwrap_or(0),
                    kind,
                },
            );
        }
        Ok(())
    }

    /// Extracts the raw bytes of every path in `target_paths` from a single
    /// layer tarball, in one pass over the archive.
    pub fn extract_files(
        &self,
        target_paths: &[&Path],
        layer_tar_path: &Path,
    ) -> Result<HashMap<PathBuf, Vec<u8>>> {
        let mut archive = open_archive(layer_tar_path)?;
        let mut remaining: std::collections::HashSet<PathBuf> =
            target_paths.iter().map(|p| strip_leading_curdir(p)).collect();
        let mut results = HashMap::new();
        let mut total_size: u64 = 0;

        for entry in archive.entries()? {
            if remaining.is_empty() {
                break;
            }
            let mut entry = entry?;
            let raw_path = entry.path()?;
            reject_hostile_path(&raw_path)?;
            let path = strip_leading_curdir(&raw_path);

            total_size += entry.size();
            if total_size > MAX_UNCOMPRESSED_BYTES {
                return Err(FsError::DecompressionBomb(MAX_UNCOMPRESSED_BYTES));
            }

            if remaining.remove(&path) {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                results.insert(path, buf);
            }
        }
        Ok(results)
    }

    /// Convenience wrapper over [`extract_files`](Self::extract_files) for a
    /// single path.
    pub fn extract_file(&self, target_path: &Path, layer_tar_path: &Path) -> Result<Vec<u8>> {
        let mut results = self.extract_files(&[target_path], layer_tar_path)?;
        results.remove(&strip_leading_curdir(target_path)).ok_or_else(|| {
            FsError::ExtractFailed(format!("{} not found in archive", target_path.display()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Builds a gzipped tar with the given (name, content) entries. Writes the
    /// name directly into the raw header bytes rather than going through
    /// `Header::set_path`/`Builder::append_data`, which validate and reject
    /// `..` components on write — real hostile tarballs aren't built with this
    /// crate's writer, so tests for the reader's own defenses need a way to
    /// produce a `..` entry at all.
    fn write_tar_gz(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let encoder =
            flate2::write::GzEncoder::new(file.reopen().unwrap(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            let name_bytes = name.as_bytes();
            header.as_mut_bytes()[0..name_bytes.len()].copy_from_slice(name_bytes);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap().flush().unwrap();
        file
    }

    #[test]
    fn dot_slash_prefix_normalizes_like_bare_path() {
        let tar = write_tar_gz(&[("./var/lib/dpkg/status", b"hello")]);
        let mut inv = FileInventory::new();
        inv.apply_layer(tar.path(), "sha256:layer1").unwrap();
        assert!(inv.files.contains_key(Path::new("var/lib/dpkg/status")));
    }

    #[test]
    fn parent_dir_component_is_rejected() {
        let tar = write_tar_gz(&[("../../etc/passwd", b"hostile")]);
        let mut inv = FileInventory::new();
        let err = inv.apply_layer(tar.path(), "sha256:layer1").unwrap_err();
        assert!(matches!(err, FsError::HostileEntry(_)));
    }

    #[test]
    fn whiteout_removes_prior_layer_file() {
        let base = write_tar_gz(&[("etc/foo.conf", b"1")]);
        let mut inv = FileInventory::new();
        inv.apply_layer(base.path(), "sha256:layer1").unwrap();
        assert!(inv.files.contains_key(Path::new("etc/foo.conf")));

        let wh = write_tar_gz(&[("etc/.wh.foo.conf", b"")]);
        inv.apply_layer(wh.path(), "sha256:layer2").unwrap();
        assert!(!inv.files.contains_key(Path::new("etc/foo.conf")));
    }

    #[test]
    fn opaque_whiteout_clears_directory_from_earlier_layers_only() {
        let base = write_tar_gz(&[("etc/a", b"1"), ("etc/b", b"2")]);
        let mut inv = FileInventory::new();
        inv.apply_layer(base.path(), "sha256:layer1").unwrap();

        let opq = write_tar_gz(&[("etc/.wh..wh..opq", b""), ("etc/c", b"3")]);
        inv.apply_layer(opq.path(), "sha256:layer2").unwrap();

        assert!(!inv.files.contains_key(Path::new("etc/a")));
        assert!(!inv.files.contains_key(Path::new("etc/b")));
        assert!(inv.files.contains_key(Path::new("etc/c")));
    }

    #[test]
    fn extract_file_rejects_hostile_entry_even_when_target_is_benign() {
        let tar = write_tar_gz(&[("../escape", b"x"), ("etc/foo", b"y")]);
        let inv = FileInventory::new();
        let err = inv.extract_file(Path::new("etc/foo"), tar.path()).unwrap_err();
        assert!(matches!(err, FsError::HostileEntry(_)));
    }

    #[test]
    fn symlink_kind_and_target_are_recorded() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let encoder =
            flate2::write::GzEncoder::new(file.reopen().unwrap(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        builder.append_link(&mut header, "bin/sh", "busybox").unwrap();
        builder.into_inner().unwrap().finish().unwrap().flush().unwrap();

        let mut inv = FileInventory::new();
        inv.apply_layer(file.path(), "sha256:layer1").unwrap();
        let meta = inv.files.get(Path::new("bin/sh")).unwrap();
        assert_eq!(meta.kind, EntryKind::Symlink(PathBuf::from("busybox")));
    }
}
