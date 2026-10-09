//! `bedrock attest`: sign an image and attach in-toto attestations as OCI
//! referrers (BEDROCK_SPEC.md 5.8). Key-based signing only; keyless signing
//! (Fulcio and Rekor) is not implemented.
pub mod artifact;
pub mod key;
pub mod statements;

use crate::oci::manifest::Descriptor;
use crate::oci::RegistryClient;
use crate::report::Report;
use anyhow::{bail, Context, Result};
use artifact::{build, sha256_digest, statement, Artifact, INDEX_TYPE, MANIFEST_TYPE};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub enum Target {
    /// An OCI image layout directory: artifacts are added to its blobs and `index.json`.
    Layout(PathBuf),
    /// An image in a registry, by tag or digest.
    Registry { client: RegistryClient, reference: String },
}

pub struct AttestRequest<'a> {
    pub key: &'a key::SigningKey,
    pub target: Target,
    /// Name recorded in the statements' subject (registry references only).
    pub subject_name: Option<String>,
    pub os: String,
    pub arch: String,
    /// SPDX document of the image being attested.
    pub spdx: Option<Value>,
    /// The `slim` report, for provenance and the optional report attestation.
    pub slim_report: Option<&'a Report>,
    pub attest_report: bool,
}

#[derive(Debug)]
pub struct Attached {
    pub predicate_type: String,
    pub digest: String,
}

pub fn run(req: AttestRequest<'_>) -> Result<Vec<Attached>> {
    let subject = match &req.target {
        Target::Layout(dir) => layout_subject(dir, &req.os, &req.arch)?,
        Target::Registry { client, reference } => {
            let (bytes, media_type) = client
                .manifest_raw(reference)?
                .with_context(|| format!("{reference} was not found in the registry"))?;
            Descriptor {
                media_type: media_type.split(';').next().unwrap_or_default().trim().to_string(),
                digest: sha256_digest(&bytes),
                size: bytes.len() as u64,
                platform: None,
            }
        }
    };
    let hex =
        subject.digest.strip_prefix("sha256:").context("subject digest is not sha256")?.to_string();
    let name = req.subject_name.as_deref();

    // Signature first, then attestations.
    let mut statements = vec![statement(None, &hex, statements::SIGN_TYPE, json!({}))];
    if let Some(p) = req.slim_report.and_then(statements::provenance) {
        statements.push(statement(name, &hex, statements::SLSA_PROVENANCE, p));
    }
    if let Some(spdx) = req.spdx.clone() {
        statements.push(statement(name, &hex, statements::SPDX, spdx));
    }
    if let (true, Some(r)) = (req.attest_report, req.slim_report) {
        statements.push(statement(name, &hex, statements::REPORT, serde_json::to_value(r)?));
    }

    let artifacts: Vec<Artifact> = statements.iter().map(|s| build(req.key, &subject, s)).collect();
    match &req.target {
        Target::Layout(dir) => attach_layout(dir, &artifacts)?,
        Target::Registry { client, .. } => attach_registry(client, &subject, &artifacts)?,
    }
    Ok(artifacts
        .into_iter()
        .map(|a| Attached { predicate_type: a.predicate_type, digest: a.manifest_digest })
        .collect())
}

/// The image manifest in a layout's `index.json` (artifacts attached earlier are skipped).
fn layout_subject(dir: &Path, os: &str, arch: &str) -> Result<Descriptor> {
    let index: Value =
        serde_json::from_slice(&std::fs::read(dir.join("index.json")).context("no index.json")?)?;
    let images: Vec<&Value> = index["manifests"]
        .as_array()
        .context("index.json has no manifests")?
        .iter()
        .filter(|m| !crate::oci::manifest::is_attached_artifact(m))
        .collect();
    let pick = match images.as_slice() {
        [one] => *one,
        many => many
            .iter()
            .find(|m| m["platform"]["os"] == os && m["platform"]["architecture"] == arch)
            .copied()
            .with_context(|| format!("no manifest for {os}/{arch} in index.json"))?,
    };
    let get = |k: &str| pick[k].as_str().map(String::from);
    Ok(Descriptor {
        media_type: get("mediaType").context("manifest entry has no mediaType")?,
        digest: get("digest").context("manifest entry has no digest")?,
        size: pick["size"].as_u64().context("manifest entry has no size")?,
        platform: None,
    })
}

fn attach_layout(dir: &Path, artifacts: &[Artifact]) -> Result<()> {
    let blobs = dir.join("blobs").join("sha256");
    std::fs::create_dir_all(&blobs)?;
    let write = |digest: &str, data: &[u8]| -> Result<()> {
        std::fs::write(blobs.join(digest.strip_prefix("sha256:").unwrap_or(digest)), data)?;
        Ok(())
    };
    let index_path = dir.join("index.json");
    let mut index: Value = serde_json::from_slice(&std::fs::read(&index_path)?)?;
    let manifests = index["manifests"].as_array_mut().context("index.json has no manifests")?;
    for a in artifacts {
        for (digest, data) in &a.blobs {
            write(digest, data)?;
        }
        write(&a.manifest_digest, &a.manifest)?;
        if !manifests.iter().any(|m| m["digest"] == a.descriptor["digest"]) {
            manifests.push(a.descriptor.clone());
        }
    }
    std::fs::write(&index_path, serde_json::to_vec(&index)?)?;
    Ok(())
}

fn attach_registry(
    client: &RegistryClient,
    subject: &Descriptor,
    artifacts: &[Artifact],
) -> Result<()> {
    for a in artifacts {
        for (digest, data) in &a.blobs {
            client.push_blob(digest, data)?;
        }
        let indexed = client.push_manifest(&a.manifest_digest, MANIFEST_TYPE, &a.manifest)?;
        // Registries without the Referrers API leave the listing to the client:
        // an index under the tag `sha256-<subject digest>` (OCI Distribution 1.1).
        if !indexed {
            let tag = subject.digest.replace(':', "-");
            let mut index = match client.manifest_raw(&tag)? {
                Some((bytes, _)) => serde_json::from_slice::<Value>(&bytes)
                    .context("existing referrers index is not valid JSON")?,
                None => json!({ "schemaVersion": 2, "mediaType": INDEX_TYPE, "manifests": [] }),
            };
            let list =
                index["manifests"].as_array_mut().context("referrers index has no manifests")?;
            if !list.iter().any(|m| m["digest"] == a.descriptor["digest"]) {
                list.push(a.descriptor.clone());
            }
            client.push_manifest(&tag, INDEX_TYPE, &serde_json::to_vec(&index)?)?;
        }
    }
    if artifacts.is_empty() {
        bail!("nothing to attach");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePrivateKey;

    #[test]
    fn layout_gets_signature_and_sbom_artifacts_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = dir.path().join("blobs/sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::write(
            dir.path().join("index.json"),
            br#"{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:abc","size":10,"platform":{"os":"linux","architecture":"amd64"}}]}"#,
        )
        .unwrap();
        let secret = p256::SecretKey::from_slice(&[3u8; 32]).unwrap();
        let pem = p256::ecdsa::SigningKey::from(secret).to_pkcs8_pem(Default::default()).unwrap();
        let key = key::SigningKey::parse(&pem, "").unwrap();
        let go = || {
            run(AttestRequest {
                key: &key,
                target: Target::Layout(dir.path().into()),
                subject_name: None,
                os: "linux".into(),
                arch: "amd64".into(),
                spdx: Some(json!({"spdxVersion": "SPDX-2.3"})),
                slim_report: None,
                attest_report: false,
            })
            .unwrap()
        };
        let first = go();
        assert_eq!(first.len(), 2); // signature + SBOM; no report, so no provenance
        let again = go();
        assert_eq!(first[0].digest, again[0].digest, "deterministic");

        let index: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("index.json")).unwrap()).unwrap();
        let listed = index["manifests"].as_array().unwrap();
        assert_eq!(listed.len(), 3, "image + 2 artifacts, no duplicates after a second run");
        let sig = listed
            .iter()
            .find(|m| {
                m["annotations"]["dev.sigstore.bundle.predicateType"] == statements::SIGN_TYPE
            })
            .unwrap();
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(
                blobs.join(sig["digest"].as_str().unwrap().trim_start_matches("sha256:")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["subject"]["digest"], "sha256:abc");
    }
}
