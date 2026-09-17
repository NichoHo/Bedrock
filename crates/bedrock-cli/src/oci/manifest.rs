use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default)]
    pub platform: Option<Platform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(default)]
    pub media_type: Option<String>,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

/// A manifest blob (or a local OCI layout's `index.json`) is either a single
/// image manifest, or an index/manifest-list naming one manifest per platform.
/// Both shapes are distinguished the same way: an index has "manifests" and no
/// "config".
enum ManifestOrIndex {
    Manifest(Manifest),
    Index(Vec<Descriptor>),
}

fn parse_manifest_or_index(data: &[u8]) -> Result<ManifestOrIndex> {
    let value: serde_json::Value = serde_json::from_slice(data)?;
    if value.get("manifests").is_some() && value.get("config").is_none() {
        #[derive(Deserialize)]
        struct Index {
            manifests: Vec<Descriptor>,
        }
        let index: Index = serde_json::from_value(value)?;
        Ok(ManifestOrIndex::Index(index.manifests))
    } else {
        Ok(ManifestOrIndex::Manifest(serde_json::from_value(value)?))
    }
}

fn select_platform<'a>(entries: &'a [Descriptor], os: &str, arch: &str) -> Option<&'a Descriptor> {
    entries
        .iter()
        .find(|d| d.platform.as_ref().is_some_and(|p| p.os == os && p.architecture == arch))
}

/// Resolves `data` (a manifest or an index) down to a single [`Manifest`] for
/// the requested platform. `fetch` retrieves another blob by digest, used when
/// `data` turns out to be an index and the selected entry must be fetched.
/// Falls back to the first entry when none declares a matching platform, so a
/// single-manifest index (or one without platform metadata) still resolves.
pub fn resolve_manifest(
    data: &[u8],
    os: &str,
    arch: &str,
    fetch: impl Fn(&str) -> Result<Vec<u8>>,
) -> Result<Manifest> {
    match parse_manifest_or_index(data).context("failed to parse manifest or index")? {
        ManifestOrIndex::Manifest(m) => Ok(m),
        ManifestOrIndex::Index(entries) => {
            let target = select_platform(&entries, os, arch)
                .or_else(|| entries.first())
                .context("manifest index is empty")?;
            let data = fetch(&target.digest)?;
            match parse_manifest_or_index(&data).context("failed to parse referenced manifest")? {
                ManifestOrIndex::Manifest(m) => Ok(m),
                ManifestOrIndex::Index(_) => {
                    bail!("nested manifest indexes (index pointing to another index) are not supported")
                }
            }
        }
    }
}
