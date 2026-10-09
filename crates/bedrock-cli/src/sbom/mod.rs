pub mod apk;
pub mod binaries;
pub mod cyclonedx;
pub mod dpkg;
pub mod node;
pub mod python;
pub mod rpm;
pub mod spdx;

use crate::fs::{EntryKind, FileInventory};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    /// Name of the source package (dpkg `Source:`, apk `o:`, rpm SOURCERPM)
    /// when the package manager records one. Advisory feeds for Debian and
    /// Alpine are keyed by it, not by the binary package name.
    pub source: Option<String>,
    pub purl: String,
    pub files: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Sbom {
    pub packages: Vec<Package>,
    /// Content hashes for every path in any package's `files`. Writers emit
    /// only files found here, so a package's list must already be filtered
    /// to regular files present in the image (see [`Sbom::new`]).
    pub file_digests: std::collections::BTreeMap<PathBuf, crate::fs::Digests>,
}

impl Sbom {
    /// Builds an SBOM, keeping only the package-owned files that exist in the
    /// final image as regular files (or hard links to them). Package
    /// databases also list directories, symlinks, and files a later layer
    /// deleted (slim images strip docs); none of those has content to hash.
    pub fn new(mut packages: Vec<Package>, inventory: &FileInventory) -> Self {
        let mut file_digests = std::collections::BTreeMap::new();
        for pkg in &mut packages {
            pkg.files.retain(|f| match inventory.files.get(f).and_then(|m| m.digests) {
                Some(d) => {
                    file_digests.insert(f.clone(), d);
                    true
                }
                None => false,
            });
            pkg.files.sort();
            pkg.files.dedup();
        }
        Self { packages, file_digests }
    }
}

/// A unique-enough identifier for one SBOM document: SPDX's `documentNamespace`
/// and CycloneDX's `serialNumber` both require a value that doesn't repeat
/// across documents. Built from a hash of the process id and current time
/// rather than pulling in a `uuid` crate for one call site.
pub fn document_id() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.update(nanos.to_le_bytes());
    let hash = hasher.finalize();
    let hex = hex::encode(hash);
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// Reads the contents of every regular file in `paths` that exists in the
/// inventory, grouping by the layer that holds each one so a layer is
/// decompressed once per call rather than once per file. Paths that are
/// missing, not regular files (a symlink's tar entry has no content), or whose
/// layer can't be resolved are left out of the result.
pub fn read_files<F>(
    inventory: &FileInventory,
    resolver: &F,
    paths: &[PathBuf],
) -> crate::fs::Result<HashMap<PathBuf, Vec<u8>>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let mut by_layer: HashMap<&str, Vec<&Path>> = HashMap::new();
    for path in paths {
        if let Some(meta) = inventory.files.get(path).filter(|m| m.kind == EntryKind::File) {
            by_layer.entry(&meta.layer_digest).or_default().push(path);
        }
    }
    let mut out = HashMap::new();
    for (layer, layer_paths) in by_layer {
        let Some(tar_path) = resolver(layer) else { continue };
        out.extend(inventory.extract_files(&layer_paths, &tar_path)?);
    }
    Ok(out)
}

/// Single-file form of [`read_files`].
pub fn read_file<F>(
    inventory: &FileInventory,
    resolver: &F,
    path: &str,
) -> crate::fs::Result<Option<Vec<u8>>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let path = PathBuf::from(path);
    Ok(read_files(inventory, resolver, std::slice::from_ref(&path))?.remove(&path))
}

/// `ID` and `VERSION_ID` from the image's os-release, used as the PURL
/// namespace and `distro` qualifier. `/etc/os-release` is a symlink to
/// `../usr/lib/os-release` on Debian, Ubuntu and Fedora, so fall back to
/// `/usr/lib/os-release` per os-release(5).
#[derive(Debug, Default)]
pub struct OsRelease {
    pub id: Option<String>,
    pub version_id: Option<String>,
}

impl OsRelease {
    pub fn read<F>(inventory: &FileInventory, resolver: &F) -> Self
    where
        F: Fn(&str) -> Option<PathBuf>,
    {
        let data = ["etc/os-release", "usr/lib/os-release"]
            .iter()
            .find_map(|p| read_file(inventory, resolver, p).ok().flatten());
        data.map(|d| Self::parse(&String::from_utf8_lossy(&d))).unwrap_or_default()
    }

    pub fn parse(text: &str) -> Self {
        let mut out = Self::default();
        for line in text.lines() {
            let unquote = |v: &str| v.trim_matches(['"', '\'']).to_string();
            if let Some(v) = line.strip_prefix("ID=") {
                out.id = Some(unquote(v));
            } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
                out.version_id = Some(unquote(v));
            }
        }
        out
    }

    /// `&distro=<id>-<version>` when both are known, else empty.
    pub fn purl_qualifier(&self) -> String {
        match (&self.id, &self.version_id) {
            (Some(id), Some(v)) => format!("&distro={id}-{v}"),
            _ => String::new(),
        }
    }
}

/// Joins a path from a package manifest onto the directory it is relative to,
/// resolving `..` (Python RECORD files list console scripts as
/// `../../../bin/foo`). Returns `None` if `..` would climb above the image root.
pub fn join_normalized(base: &Path, rel: &str) -> Option<PathBuf> {
    let mut out: Vec<&str> = if rel.starts_with('/') {
        Vec::new()
    } else {
        base.to_str()?.split('/').filter(|s| !s.is_empty()).collect()
    };
    for part in rel.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop()?;
            }
            p => out.push(p),
        }
    }
    Some(out.join("/").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_normalized_resolves_parent_components() {
        let base = Path::new("usr/lib/python3/site-packages");
        assert_eq!(
            join_normalized(base, "requests/api.py"),
            Some("usr/lib/python3/site-packages/requests/api.py".into())
        );
        assert_eq!(join_normalized(base, "../../../bin/flask"), Some("usr/bin/flask".into()));
        assert_eq!(join_normalized(base, "/etc/abs.conf"), Some("etc/abs.conf".into()));
        assert_eq!(join_normalized(Path::new("a"), "../../x"), None);
    }

    #[test]
    fn os_release_parses_quoted_values() {
        let r = OsRelease::parse("NAME=\"Fedora\"\nID=fedora\nVERSION_ID=40\n");
        assert_eq!(r.id.as_deref(), Some("fedora"));
        assert_eq!(r.purl_qualifier(), "&distro=fedora-40");
    }
}
