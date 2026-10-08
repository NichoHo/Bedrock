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
    let mut value: serde_json::Value = serde_json::from_slice(data)?;
    // Signatures, SBOMs and attestations attached to an image are listed in the
    // same index but are not images, whatever platform is asked for.
    if let Some(entries) = value.get_mut("manifests").and_then(|m| m.as_array_mut()) {
        entries.retain(|m| m.get("artifactType").is_none());
    }
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

/// Picks the index entry for `os`/`arch`. Never falls back to a different
/// platform: silently returning amd64 for an arm64 request would produce an
/// SBOM (and later a pruned image) for the wrong image. The one fallback is an
/// index with a single entry and no platform metadata at all, which is what
/// many local OCI layouts look like.
fn select_platform<'a>(entries: &'a [Descriptor], os: &str, arch: &str) -> Result<&'a Descriptor> {
    if let Some(d) = entries
        .iter()
        .find(|d| d.platform.as_ref().is_some_and(|p| p.os == os && p.architecture == arch))
    {
        return Ok(d);
    }
    let declared: std::collections::BTreeSet<String> = entries
        .iter()
        .filter_map(|d| d.platform.as_ref())
        .map(|p| format!("{}/{}", p.os, p.architecture))
        .collect();
    match (entries, declared.is_empty()) {
        ([], _) => bail!("manifest index is empty"),
        ([only], true) => Ok(only),
        (_, true) => bail!(
            "manifest index has {} entries and none declares a platform, so {os}/{arch} can't be chosen",
            entries.len()
        ),
        (_, false) => bail!(
            "image has no {os}/{arch} manifest; available platforms: {}",
            // unknown/unknown entries are build attestations, not images.
            declared
                .iter()
                .filter(|p| *p != "unknown/unknown")
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Checks that `data` hashes to `digest` (`sha256:<hex>`). Content fetched by
/// digest must be verified, or a registry or a tampered layout can substitute
/// a different manifest under a pinned reference.
pub fn verify_digest(data: &[u8], digest: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    let expected = digest
        .strip_prefix("sha256:")
        .with_context(|| format!("unsupported digest algorithm in {digest:?} (only sha256)"))?;
    let actual = hex::encode(Sha256::digest(data));
    if actual != expected {
        bail!("digest mismatch: expected sha256:{expected}, got sha256:{actual}");
    }
    Ok(())
}

/// Resolves `data` (a manifest or an index) down to a single [`Manifest`] for
/// the requested platform. `fetch` retrieves another blob by digest, used when
/// `data` turns out to be an index and the selected entry must be fetched.
pub fn resolve_manifest(
    data: &[u8],
    os: &str,
    arch: &str,
    fetch: impl Fn(&str) -> Result<Vec<u8>>,
) -> Result<Manifest> {
    match parse_manifest_or_index(data).context("failed to parse manifest or index")? {
        ManifestOrIndex::Manifest(m) => Ok(m),
        ManifestOrIndex::Index(entries) => {
            let target = select_platform(&entries, os, arch)?;
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

#[cfg(test)]
mod tests {
    #[test]
    fn attached_artifacts_in_an_index_are_not_images() {
        let idx = br#"{"schemaVersion":2,"manifests":[
          {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aa","size":1},
          {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bb","size":1,"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json"}]}"#;
        match super::parse_manifest_or_index(idx).unwrap() {
            super::ManifestOrIndex::Index(entries) => assert_eq!(entries.len(), 1),
            _ => panic!("expected an index"),
        }
    }

    use super::*;

    fn index(platforms: &[Option<(&str, &str)>]) -> Vec<u8> {
        let manifests: Vec<_> = platforms
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut d = serde_json::json!({
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": format!("sha256:{:064x}", i),
                    "size": 1
                });
                if let Some((os, arch)) = p {
                    d["platform"] = serde_json::json!({"os": os, "architecture": arch});
                }
                d
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({"schemaVersion": 2, "manifests": manifests}))
            .unwrap()
    }

    /// Returns a manifest whose config digest records which index entry was fetched.
    fn fetch(digest: &str) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "config": {"mediaType": "x", "digest": digest, "size": 1},
            "layers": []
        }))
        .unwrap())
    }

    #[test]
    fn picks_matching_platform() {
        let data = index(&[Some(("linux", "amd64")), Some(("linux", "arm64"))]);
        let m = resolve_manifest(&data, "linux", "arm64", fetch).unwrap();
        assert_eq!(m.config.digest, format!("sha256:{:064x}", 1));
    }

    #[test]
    fn missing_platform_is_an_error_not_a_fallback() {
        let data = index(&[Some(("linux", "amd64"))]);
        let err = resolve_manifest(&data, "linux", "arm64", fetch).unwrap_err();
        assert!(format!("{err:#}").contains("linux/amd64"));
    }

    #[test]
    fn single_entry_without_platform_still_resolves() {
        let data = index(&[None]);
        assert!(resolve_manifest(&data, "linux", "arm64", fetch).is_ok());
    }

    #[test]
    fn multiple_entries_without_platform_is_ambiguous() {
        let data = index(&[None, None]);
        assert!(resolve_manifest(&data, "linux", "amd64", fetch).is_err());
    }

    #[test]
    fn verify_digest_accepts_match_and_rejects_mismatch() {
        let digest = "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
        assert!(verify_digest(b"foo", digest).is_ok());
        assert!(verify_digest(b"bar", digest).is_err());
        assert!(verify_digest(b"foo", "sha512:abc").is_err());
    }
}
