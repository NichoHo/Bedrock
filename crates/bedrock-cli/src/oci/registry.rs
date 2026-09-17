use crate::oci::manifest::resolve_manifest;
use crate::oci::{Manifest, OciError};
use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::Deserialize;

const MANIFEST_ACCEPT: &str = "application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.index.v1+json";

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

pub struct RegistryClient {
    client: Client,
    registry: String,
    repository: String,
    token: Option<String>,
}

impl RegistryClient {
    pub fn new(registry: &str, repository: &str) -> Self {
        Self {
            client: Client::new(),
            registry: registry.to_string(),
            repository: repository.to_string(),
            token: None,
        }
    }

    pub fn authenticate(&mut self) -> Result<()> {
        let ping_url = format!("https://{}/v2/", self.registry);
        let resp = self.client.get(&ping_url).send().context("registry ping failed")?;

        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(());
        }

        let auth_header = resp
            .headers()
            .get("Www-Authenticate")
            .context("registry returned 401 with no Www-Authenticate challenge")?;
        let auth_str = auth_header.to_str().context("non-UTF8 Www-Authenticate header")?;
        let params = auth_str
            .strip_prefix("Bearer ")
            .with_context(|| format!("unsupported auth scheme: {auth_str}"))?;

        let mut realm = "";
        let mut service = "";
        for part in params.split(',') {
            let part = part.trim();
            if let Some(r) = part.strip_prefix("realm=\"") {
                realm = r.trim_end_matches('"');
            } else if let Some(s) = part.strip_prefix("service=\"") {
                service = s.trim_end_matches('"');
            }
        }
        if realm.is_empty() {
            anyhow::bail!("Www-Authenticate challenge had no realm: {auth_str}");
        }

        let mut auth_url = format!("{}?scope=repository:{}:pull", realm, self.repository);
        if !service.is_empty() {
            auth_url.push_str(&format!("&service={}", service));
        }

        let token_resp =
            self.client.get(&auth_url).send().context("token endpoint request failed")?;
        if !token_resp.status().is_success() {
            anyhow::bail!("token endpoint returned {}", token_resp.status());
        }
        let tr: TokenResponse =
            token_resp.json().context("token endpoint returned invalid JSON")?;
        self.token = tr.token.or(tr.access_token);
        if self.token.is_none() {
            anyhow::bail!("token endpoint response had neither `token` nor `access_token`");
        }
        Ok(())
    }

    fn fetch_manifest_bytes(&self, tag_or_digest: &str) -> Result<Vec<u8>> {
        let url =
            format!("https://{}/v2/{}/manifests/{}", self.registry, self.repository, tag_or_digest);
        let mut req = self.client.get(&url).header("Accept", MANIFEST_ACCEPT);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let resp = req.send().context("manifest request failed")?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(OciError::ManifestNotFound.into());
        }
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            anyhow::bail!("registry returned {status} fetching manifest {tag_or_digest}: {body}");
        }
        Ok(resp.bytes().context("failed to read manifest response body")?.to_vec())
    }

    /// Fetches the manifest for `tag_or_digest` and resolves it (following an
    /// index/manifest-list if the registry returns one) to the manifest for
    /// `os`/`arch`.
    pub fn resolve_manifest(&self, tag_or_digest: &str, os: &str, arch: &str) -> Result<Manifest> {
        let data = self.fetch_manifest_bytes(tag_or_digest)?;
        resolve_manifest(&data, os, arch, |digest| self.fetch_manifest_bytes(digest))
    }

    pub fn fetch_blob(&self, digest: &str, dest_path: &std::path::Path) -> Result<()> {
        let url = format!("https://{}/v2/{}/blobs/{}", self.registry, self.repository, digest);
        let mut req = self.client.get(&url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let mut resp = req.send().context("blob request failed")?;
        let status = resp.status();
        if !status.is_success() {
            return Err(OciError::BlobNotFound(format!("{digest} ({status})")).into());
        }

        let digest_clean = digest.strip_prefix("sha256:").unwrap_or(digest);
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = std::fs::File::create(dest_path)?;
        let mut buf = [0; 8192];
        use std::io::{Read, Write};
        loop {
            let n = resp.read(&mut buf).context("error reading blob response body")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])?;
        }

        let hash = hex::encode(hasher.finalize());
        if hash != digest_clean {
            let _ = std::fs::remove_file(dest_path);
            return Err(anyhow::anyhow!(OciError::InvalidDigest(format!(
                "Digest mismatch: expected {}, got {}",
                digest_clean, hash
            ))));
        }

        Ok(())
    }
}
