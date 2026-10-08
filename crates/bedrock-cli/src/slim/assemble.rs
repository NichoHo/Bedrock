//! Builds the pruned image as an OCI layout. Output is deterministic: entries
//! follow the original layer and tar order, timestamps are fixed, gzip carries
//! no mtime, and JSON documents have sorted keys. The same input and keep set
//! always produce the same digests.
use crate::fs::{open_archive, strip_leading_curdir, EntryKind, FileInventory};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Fixed time for everything Bedrock writes: the Unix epoch.
const EPOCH: &str = "1970-01-01T00:00:00Z";
const LAYER_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

pub struct AssembleInput<'a> {
    pub inventory: &'a FileInventory,
    /// (digest, tar path) in image order.
    pub layers: &'a [(String, PathBuf)],
    pub keep: &'a BTreeSet<PathBuf>,
    /// Replacement contents for files rewritten by the pruner (package databases).
    pub overrides: &'a BTreeMap<PathBuf, Vec<u8>>,
    pub config_json: &'a [u8],
    /// Keep the original layer structure, reusing untouched layers byte for byte.
    pub preserve_layers: bool,
    pub out: &'a Path,
}

#[derive(Debug)]
pub struct Assembled {
    pub manifest_digest: String,
    pub config_digest: String,
    pub size_bytes: u64,
    pub layers: usize,
}

struct HashWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    n: u64,
}

impl<W: Write> HashWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, hasher: Sha256::new(), n: 0 }
    }
    fn finish(self) -> (W, String, u64) {
        (self.inner, hex::encode(self.hasher.finalize()), self.n)
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.n += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct LayerBlob {
    digest: String,
    diff_id: String,
    size: u64,
}

type Gz = flate2::write::GzEncoder<HashWriter<std::fs::File>>;

/// One gzip layer being written: tar -> hash (diff id) -> gzip -> hash (blob digest) -> file.
struct LayerWriter {
    tar: tar::Builder<HashWriter<Gz>>,
    tmp: PathBuf,
    entries: usize,
}

impl LayerWriter {
    fn new(blobs: &Path, n: usize) -> Result<Self> {
        let tmp = blobs.join(format!(".tmp-layer-{n}"));
        let file = std::fs::File::create(&tmp)?;
        // No mtime and a fixed level keep the gzip stream reproducible; the best level
        // because the output is written once and pulled many times.
        let gz = flate2::GzBuilder::new()
            .mtime(0)
            .write(HashWriter::new(file), flate2::Compression::best());
        let mut tar = tar::Builder::new(HashWriter::new(gz));
        tar.mode(tar::HeaderMode::Complete);
        Ok(Self { tar, tmp, entries: 0 })
    }

    fn finish(self, blobs: &Path) -> Result<LayerBlob> {
        let uncompressed = self.tar.into_inner()?;
        let (gz, diff_hex, _) = uncompressed.finish();
        let compressed = gz.finish()?;
        let (file, digest_hex, size) = compressed.finish();
        file.sync_all()?;
        std::fs::rename(&self.tmp, blobs.join(&digest_hex))?;
        Ok(LayerBlob {
            digest: format!("sha256:{digest_hex}"),
            diff_id: format!("sha256:{diff_hex}"),
            size,
        })
    }
}

/// Appends one entry copied from an original layer. `false` for entry types
/// the pruned image does not carry (devices, fifos).
fn copy_entry<R: Read, W: Write>(
    builder: &mut tar::Builder<W>,
    entry: &mut tar::Entry<R>,
    path: &Path,
    replacement: Option<&[u8]>,
    mtime: Option<u64>,
) -> Result<bool> {
    let mut header = entry.header().clone();
    if let Some(m) = mtime {
        header.set_mtime(m);
    }
    use tar::EntryType as T;
    match header.entry_type() {
        T::Regular | T::Continuous => match replacement {
            Some(data) => {
                header.set_size(data.len() as u64);
                builder.append_data(&mut header, path, data)?;
            }
            None => builder.append_data(&mut header, path, entry)?,
        },
        T::Directory => builder.append_data(&mut header, path, std::io::empty())?,
        T::Symlink | T::Link => {
            let target = entry.link_name()?.map(|l| l.to_path_buf()).unwrap_or_default();
            let target =
                if header.entry_type() == T::Link { strip_leading_curdir(&target) } else { target };
            builder.append_link(&mut header, path, target)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// True if every entry of the layer survives unchanged, so its blob can be reused as is.
fn layer_unchanged(input: &AssembleInput<'_>, digest: &str, tar_path: &Path) -> Result<bool> {
    let mut magic = [0u8; 2];
    let gz = std::fs::File::open(tar_path)?.read_exact(&mut magic).is_ok() && magic == [0x1f, 0x8b];
    if !gz {
        return Ok(false); // the pruned layer is always gzip
    }
    let mut archive = open_archive(tar_path)?;
    for entry in archive.entries()? {
        let entry = entry?;
        let path = strip_leading_curdir(&entry.path()?);
        if path.as_os_str().is_empty() {
            continue;
        }
        let visible = input.inventory.files.get(&path).is_some_and(|m| m.layer_digest == digest);
        let plain_type = matches!(
            entry.header().entry_type(),
            tar::EntryType::Regular
                | tar::EntryType::Directory
                | tar::EntryType::Symlink
                | tar::EntryType::Link
        );
        if !(visible
            && plain_type
            && input.keep.contains(&path)
            && !input.overrides.contains_key(&path))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Streams one original layer, appending the entries `keep` selects that this layer owns.
fn copy_layer(
    input: &AssembleInput<'_>,
    digest: &str,
    tar_path: &Path,
    out: &mut LayerWriter,
    emitted: &mut HashSet<PathBuf>,
) -> Result<()> {
    let mut archive = open_archive(tar_path)?;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = strip_leading_curdir(&entry.path()?);
        // The root directory entry ("./") has no name to write; extractors create it implicitly.
        if path.as_os_str().is_empty() {
            continue;
        }
        let Some(meta) = input.inventory.files.get(&path) else { continue };
        if meta.layer_digest != digest || !input.keep.contains(&path) {
            continue;
        }
        if let EntryKind::HardLink(target) = &meta.kind {
            if !emitted.contains(&strip_leading_curdir(target)) {
                bail!(
                    "hard link {} points at {}, which is not earlier in the pruned layer",
                    path.display(),
                    target.display()
                );
            }
        }
        let replacement = input.overrides.get(&path).map(Vec::as_slice);
        if copy_entry(&mut out.tar, &mut entry, &path, replacement, Some(0))? {
            out.entries += 1;
            emitted.insert(path);
        }
    }
    Ok(())
}

pub fn assemble(input: &AssembleInput<'_>) -> Result<Assembled> {
    let blobs = input.out.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs)?;
    std::fs::write(input.out.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#)?;

    let original: Value =
        serde_json::from_slice(input.config_json).context("image config is not JSON")?;
    let original_diff_ids: Vec<String> = original["rootfs"]["diff_ids"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let mut layers: Vec<LayerBlob> = Vec::new();
    if input.preserve_layers {
        for (i, (digest, tar_path)) in input.layers.iter().enumerate() {
            let reusable = original_diff_ids
                .get(i)
                .filter(|_| layer_unchanged(input, digest, tar_path).unwrap_or(false));
            if let Some(diff_id) = reusable {
                let hex_digest = digest.strip_prefix("sha256:").unwrap_or(digest);
                std::fs::copy(tar_path, blobs.join(hex_digest))?;
                layers.push(LayerBlob {
                    digest: digest.clone(),
                    diff_id: diff_id.clone(),
                    size: std::fs::metadata(tar_path)?.len(),
                });
                continue;
            }
            let mut w = LayerWriter::new(&blobs, i)?;
            copy_layer(input, digest, tar_path, &mut w, &mut HashSet::new())?;
            if w.entries == 0 {
                drop(w.tar);
                let _ = std::fs::remove_file(&w.tmp);
                continue; // nothing of this layer survives
            }
            layers.push(w.finish(&blobs)?);
        }
    } else {
        let mut w = LayerWriter::new(&blobs, 0)?;
        let mut emitted = HashSet::new();
        for (digest, tar_path) in input.layers {
            copy_layer(input, digest, tar_path, &mut w, &mut emitted)?;
        }
        layers.push(w.finish(&blobs)?);
    }

    // Config: the original, minus anything that records when or where it was built.
    let mut config = original;
    let obj = config.as_object_mut().context("image config is not an object")?;
    for k in ["container", "container_config", "docker_version", "id", "parent", "created"] {
        obj.remove(k);
    }
    obj.insert("created".into(), json!(EPOCH));
    obj.insert("rootfs".into(), json!({ "type": "layers", "diff_ids": layers.iter().map(|l| &l.diff_id).collect::<Vec<_>>() }));
    let history: Vec<Value> = layers
        .iter()
        .map(|_| json!({ "created": EPOCH, "created_by": format!("bedrock slim {}", env!("CARGO_PKG_VERSION")) }))
        .collect();
    obj.insert("history".into(), Value::Array(history));
    let config_bytes = serde_json::to_vec(&config)?;
    let config_digest = write_blob(&blobs, &config_bytes)?;

    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config_bytes.len(),
        },
        "layers": layers.iter().map(|l| json!({ "mediaType": LAYER_TYPE, "digest": l.digest, "size": l.size })).collect::<Vec<_>>(),
    });
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_digest = write_blob(&blobs, &manifest_bytes)?;

    let mut entry = json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": manifest_digest,
        "size": manifest_bytes.len(),
    });
    if let (Some(os), Some(arch)) = (config["os"].as_str(), config["architecture"].as_str()) {
        entry["platform"] = json!({ "os": os, "architecture": arch });
    }
    let index = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [entry],
    });
    std::fs::write(input.out.join("index.json"), serde_json::to_vec(&index)?)?;

    Ok(Assembled {
        manifest_digest,
        config_digest,
        size_bytes: layers.iter().map(|l| l.size).sum(),
        layers: layers.len(),
    })
}

fn write_blob(blobs: &Path, data: &[u8]) -> Result<String> {
    let hex_digest = hex::encode(Sha256::digest(data));
    std::fs::write(blobs.join(&hex_digest), data)?;
    Ok(format!("sha256:{hex_digest}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::OciLayout;

    fn write_layer(
        dir: &Path,
        name: &str,
        entries: &[(&str, &[u8])],
        links: &[(&str, &str)],
    ) -> (String, PathBuf) {
        let path = dir.join(name);
        let enc = flate2::write::GzEncoder::new(
            std::fs::File::create(&path).unwrap(),
            flate2::Compression::fast(),
        );
        let mut b = tar::Builder::new(enc);
        for (n, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_path(n).unwrap();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_uid(1000);
            h.set_gid(1001);
            h.set_mtime(1_700_000_000);
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        for (n, t) in links {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            h.set_uid(1000);
            h.set_gid(1001);
            h.set_mtime(1_700_000_000);
            b.append_link(&mut h, n, t).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap();
        let digest =
            format!("sha256:{}", hex::encode(Sha256::digest(std::fs::read(&path).unwrap())));
        (digest, path)
    }

    fn fixture() -> (tempfile::TempDir, Vec<(String, PathBuf)>, FileInventory) {
        let dir = tempfile::tempdir().unwrap();
        let l1 = write_layer(
            dir.path(),
            "l1.tar.gz",
            &[("bin/app", b"APP"), ("etc/unused", b"nope"), ("etc/db", b"old")],
            &[],
        );
        let l2 =
            write_layer(dir.path(), "l2.tar.gz", &[("etc/db", b"new")], &[("bin/link", "app")]);
        let layers = vec![l1, l2];
        let mut inv = FileInventory::new();
        for (d, p) in &layers {
            inv.apply_layer(p, d).unwrap();
        }
        (dir, layers, inv)
    }

    fn keep(paths: &[&str]) -> BTreeSet<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    const CONFIG: &[u8] = br#"{"architecture":"amd64","os":"linux","created":"2024-01-01T00:00:00Z","container":"abc","config":{"Entrypoint":["/bin/app"],"User":"app"},"rootfs":{"type":"layers","diff_ids":["sha256:a","sha256:b"]}}"#;

    fn run(
        layers: &[(String, PathBuf)],
        inv: &FileInventory,
        keep: &BTreeSet<PathBuf>,
        overrides: &BTreeMap<PathBuf, Vec<u8>>,
        preserve: bool,
        out: &Path,
    ) -> Assembled {
        assemble(&AssembleInput {
            inventory: inv,
            layers,
            keep,
            overrides,
            config_json: CONFIG,
            preserve_layers: preserve,
            out,
        })
        .unwrap()
    }

    #[test]
    fn single_layer_has_only_kept_entries_with_fixed_times_and_original_owners() {
        let (dir, layers, inv) = fixture();
        let out = dir.path().join("out");
        let a = run(
            &layers,
            &inv,
            &keep(&["bin/app", "bin/link", "etc/db"]),
            &BTreeMap::new(),
            false,
            &out,
        );
        assert_eq!(a.layers, 1);

        let layout = OciLayout::new(&out);
        let m = layout.resolve_manifest("linux", "amd64").unwrap(); // also verifies digests
        let blob = layout.get_blob_path(&m.layers[0].digest).unwrap();
        let mut ar = open_archive(&blob).unwrap();
        let mut seen = BTreeMap::new();
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let mut data = Vec::new();
            e.read_to_end(&mut data).unwrap();
            seen.insert(
                e.path().unwrap().to_string_lossy().into_owned(),
                (e.header().mtime().unwrap(), e.header().uid().unwrap(), data),
            );
        }
        assert_eq!(
            seen.keys().map(String::as_str).collect::<Vec<_>>(),
            ["bin/app", "bin/link", "etc/db"]
        );
        assert_eq!(seen["etc/db"].2, b"new", "the upper layer's version wins");
        assert!(seen.values().all(|v| v.0 == 0), "mtime is fixed");
        assert_eq!(seen["bin/app"].1, 1000, "ownership is preserved");

        let cfg: Value = serde_json::from_slice(
            &std::fs::read(layout.get_blob_path(&m.config.digest).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(cfg["created"], EPOCH);
        assert!(cfg.get("container").is_none());
        assert_eq!(cfg["config"]["Entrypoint"][0], "/bin/app");
        assert_eq!(cfg["rootfs"]["diff_ids"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn output_is_reproducible() {
        let (dir, layers, inv) = fixture();
        let k = keep(&["bin/app", "etc/db"]);
        let a = run(&layers, &inv, &k, &BTreeMap::new(), false, &dir.path().join("o1"));
        let b = run(&layers, &inv, &k, &BTreeMap::new(), false, &dir.path().join("o2"));
        assert_eq!(a.manifest_digest, b.manifest_digest);
    }

    #[test]
    fn overrides_replace_file_contents() {
        let (dir, layers, inv) = fixture();
        let out = dir.path().join("out");
        let ov = BTreeMap::from([(PathBuf::from("etc/db"), b"rewritten".to_vec())]);
        run(&layers, &inv, &keep(&["etc/db"]), &ov, false, &out);
        let layout = OciLayout::new(&out);
        let m = layout.resolve_manifest("linux", "amd64").unwrap();
        let mut ar = open_archive(&layout.get_blob_path(&m.layers[0].digest).unwrap()).unwrap();
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        let mut data = String::new();
        e.read_to_string(&mut data).unwrap();
        assert_eq!(data, "rewritten");
    }

    #[test]
    fn preserve_layers_reuses_untouched_layers_and_drops_emptied_ones() {
        let (dir, layers, inv) = fixture();
        // Layer 2 (db override + link) keeps everything it owns -> reused byte for byte.
        // Layer 1 loses etc/unused and etc/db (overridden above) -> rewritten.
        let out = dir.path().join("out");
        let a = run(
            &layers,
            &inv,
            &keep(&["bin/app", "bin/link", "etc/db"]),
            &BTreeMap::new(),
            true,
            &out,
        );
        assert_eq!(a.layers, 2);
        let m = OciLayout::new(&out).resolve_manifest("linux", "amd64").unwrap();
        assert_ne!(m.layers[0].digest, layers[0].0, "layer 1 had to change");
        assert_eq!(m.layers[1].digest, layers[1].0, "layer 2 is reused");

        let out2 = dir.path().join("out2");
        let a = run(&layers, &inv, &keep(&["bin/link", "etc/db"]), &BTreeMap::new(), true, &out2);
        assert_eq!(a.layers, 1, "layer 1 has nothing left, so it is dropped");
    }
}
