//! Reads the `docker save` archive format: a tar holding `manifest.json`, an
//! image config, and one tar per layer.
//!
//! The layer tars are copied out to a scratch directory under their SHA-256,
//! so the rest of the pipeline sees them exactly like blobs in a registry
//! cache. Entry names from the archive are only ever used as lookup keys,
//! never as filesystem paths, so a hostile archive can't write outside the
//! scratch directory.
use crate::oci::manifest::{Descriptor, Manifest};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// `manifest.json` is tiny in practice; cap it so a hostile one can't be buffered whole.
const MAX_MANIFEST_BYTES: u64 = 16 << 20;

#[derive(Deserialize)]
struct ArchiveImage {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Option<Vec<String>>,
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

/// Owns the scratch directory; blobs disappear when this is dropped.
pub struct DockerArchive {
    dir: tempfile::TempDir,
}

impl DockerArchive {
    pub fn blob_path(&self, digest: &str) -> Result<PathBuf> {
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("invalid digest {digest:?}");
        }
        Ok(self.dir.path().join(hex))
    }

    /// Unpacks the layers and config of the (first) image in `tar_path`.
    pub fn open(tar_path: &Path) -> Result<(Manifest, Self)> {
        let manifest_json = read_entry(tar_path, "manifest.json")?.with_context(|| {
            format!(
                "{} has no manifest.json, so it isn't a `docker save` archive \
                 (to use an OCI layout, extract it to a directory first)",
                tar_path.display()
            )
        })?;
        let images: Vec<ArchiveImage> =
            serde_json::from_slice(&manifest_json).context("failed to parse manifest.json")?;
        let image = images.first().context("manifest.json lists no images")?;
        if images.len() > 1 {
            let tags: Vec<_> = images.iter().map(|i| i.repo_tags.iter().flatten().next()).collect();
            eprintln!(
                "Warning: archive holds {} images; using the first ({:?}), ignoring {:?}",
                images.len(),
                tags[0],
                &tags[1..]
            );
        }

        let wanted: HashSet<&str> = std::iter::once(image.config.as_str())
            .chain(image.layers.iter().map(String::as_str))
            .collect();
        let this = Self { dir: tempfile::tempdir().context("failed to create scratch directory")? };
        let extracted = this.extract(tar_path, &wanted)?;

        let describe = |name: &str, media_type: &str| -> Result<Descriptor> {
            let (digest, size) = extracted.get(name).with_context(|| {
                format!("{name} is listed in manifest.json but is not a file in the archive")
            })?;
            Ok(Descriptor {
                media_type: media_type.to_string(),
                digest: format!("sha256:{digest}"),
                size: *size,
                platform: None,
            })
        };
        let manifest = Manifest {
            schema_version: 2,
            media_type: None,
            config: describe(&image.config, "application/vnd.docker.container.image.v1+json")?,
            layers: image
                .layers
                .iter()
                .map(|l| describe(l, "application/vnd.docker.image.rootfs.diff.tar"))
                .collect::<Result<_>>()?,
        };
        Ok((manifest, this))
    }

    /// Copies each regular-file entry named in `wanted` into the scratch
    /// directory as `<sha256>`. Returns entry name -> (hex digest, size).
    fn extract(
        &self,
        tar_path: &Path,
        wanted: &HashSet<&str>,
    ) -> Result<HashMap<String, (String, u64)>> {
        let mut found = HashMap::new();
        let mut archive = tar::Archive::new(File::open(tar_path)?);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let name = entry_name(&entry);
            if !entry.header().entry_type().is_file() || !wanted.contains(name.as_str()) {
                continue;
            }
            if found.contains_key(&name) {
                continue; // a later duplicate entry must not replace the first
            }
            let partial = self.dir.path().join(format!("{}.partial", found.len()));
            let mut out = File::create(&partial)?;
            let (mut hasher, mut size, mut buf) = (Sha256::new(), 0u64, [0u8; 64 * 1024]);
            loop {
                let n = entry.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                out.write_all(&buf[..n])?;
                size += n as u64;
            }
            drop(out);
            let digest = hex::encode(hasher.finalize());
            std::fs::rename(&partial, self.dir.path().join(&digest))?;
            found.insert(name, (digest, size));
        }
        Ok(found)
    }
}

/// An entry's path as the archive wrote it, minus any leading `./`.
fn entry_name<R: Read>(entry: &tar::Entry<R>) -> String {
    let raw = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
    raw.trim_start_matches("./").to_string()
}

/// Reads one named file from the archive, or `None` if it isn't there.
fn read_entry(tar_path: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    let mut archive = tar::Archive::new(File::open(tar_path)?);
    for entry in archive.entries()? {
        let entry = entry?;
        if entry_name(&entry) == name && entry.header().entry_type().is_file() {
            let mut data = Vec::new();
            entry.take(MAX_MANIFEST_BYTES).read_to_end(&mut data)?;
            return Ok(Some(data));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut b = tar::Builder::new(file.reopen().unwrap());
        for (name, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, *data).unwrap();
        }
        b.finish().unwrap();
        file
    }

    #[test]
    fn unpacks_layers_under_their_digest() {
        let manifest =
            br#"[{"Config":"cfg.json","RepoTags":["x:1"],"Layers":["l0/layer.tar","l1/layer.tar"]}]"#;
        let tar = build(&[
            ("manifest.json", manifest),
            ("cfg.json", b"{}"),
            ("l0/layer.tar", b"layer zero"),
            ("l1/layer.tar", b"layer one"),
        ]);
        let (m, archive) = DockerArchive::open(tar.path()).unwrap();
        assert_eq!(m.layers.len(), 2);
        assert_eq!(m.layers[0].size, 10);
        let p = archive.blob_path(&m.layers[1].digest).unwrap();
        assert_eq!(std::fs::read(p).unwrap(), b"layer one");
        assert_eq!(std::fs::read(archive.blob_path(&m.config.digest).unwrap()).unwrap(), b"{}");
    }

    #[test]
    fn missing_layer_and_missing_manifest_are_errors() {
        let tar =
            build(&[("manifest.json", br#"[{"Config":"c","Layers":["nope"]}]"#), ("c", b"{}")]);
        let err = DockerArchive::open(tar.path()).err().unwrap();
        assert!(format!("{err:#}").contains("nope"));

        let tar = build(&[("other", b"x")]);
        assert!(DockerArchive::open(tar.path()).is_err());
    }
}
