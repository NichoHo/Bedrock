//! Builds minimal, valid OCI image layouts on disk for integration tests, so
//! test fixtures are generated deterministically in Rust at test time instead
//! of being committed as binary blobs (previously produced by ad hoc Python
//! scripts that weren't run by any committed, deterministic process).
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub struct LayoutBuilder {
    root: PathBuf,
}

impl LayoutBuilder {
    pub fn new(root: &Path) -> Self {
        fs::create_dir_all(root.join("blobs/sha256")).unwrap();
        fs::write(root.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
        Self { root: root.to_path_buf() }
    }

    /// Writes one gzip-compressed tar layer from (path, content) entries and
    /// returns its digest (without the `sha256:` prefix).
    pub fn layer(&self, entries: &[(&str, &[u8])]) -> String {
        self.layer_with_symlinks(entries, &[])
    }

    /// Like [`layer`](Self::layer), plus (link path, target) symlink entries.
    pub fn layer_with_symlinks(&self, entries: &[(&str, &[u8])], links: &[(&str, &str)]) -> String {
        let mut buf = Vec::new();
        {
            let encoder = flate2::write::GzEncoder::new(&mut buf, flate2::Compression::fast());
            let mut builder = tar::Builder::new(encoder);
            for (name, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(name).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *data).unwrap();
            }
            for (name, target) in links {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header.set_mode(0o777);
                builder.append_link(&mut header, name, target).unwrap();
            }
            builder.into_inner().unwrap().finish().unwrap();
        }
        self.write_blob(&buf)
    }

    /// A layer whose entries carry explicit file modes (e.g. setuid).
    pub fn layer_with_modes(&self, entries: &[(&str, &[u8], u32)]) -> String {
        let mut buf = Vec::new();
        {
            let encoder = flate2::write::GzEncoder::new(&mut buf, flate2::Compression::fast());
            let mut builder = tar::Builder::new(encoder);
            for (name, data, mode) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(name).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(*mode);
                header.set_cksum();
                builder.append(&header, *data).unwrap();
            }
            builder.into_inner().unwrap().finish().unwrap();
        }
        self.write_blob(&buf)
    }

    fn write_blob(&self, data: &[u8]) -> String {
        let digest = hex::encode(Sha256::digest(data));
        fs::write(self.root.join("blobs/sha256").join(&digest), data).unwrap();
        digest
    }

    /// Finalizes the layout: writes an empty config blob, a manifest
    /// referencing `layer_digests` in order, and `index.json` pointing at it.
    pub fn finish(&self, layer_digests: &[String]) {
        self.finish_with_config(layer_digests, b"{}");
    }

    /// Like [`finish`](Self::finish), with a chosen image config JSON.
    pub fn finish_with_config(&self, layer_digests: &[String], config: &[u8]) {
        let config_digest = self.write_blob(config);

        let layers: Vec<_> = layer_digests
            .iter()
            .map(|d| {
                let size = fs::metadata(self.root.join("blobs/sha256").join(d)).unwrap().len();
                serde_json::json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": format!("sha256:{d}"),
                    "size": size
                })
            })
            .collect();

        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{config_digest}"),
                "size": config.len()
            },
            "layers": layers
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_digest = self.write_blob(&manifest_bytes);

        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": format!("sha256:{manifest_digest}"),
                "size": manifest_bytes.len()
            }]
        });
        fs::write(self.root.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();
    }
}
