use crate::{Manifest, OciError, Result};
use reqwest::Client;
use serde::Deserialize;

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

    pub async fn authenticate(&mut self) -> Result<()> {
        // Very basic auth for docker.io
        if self.registry == "registry-1.docker.io" {
            let auth_url = format!(
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
                self.repository
            );
            let resp = self.client.get(&auth_url).send().await?;
            if resp.status().is_success() {
                let token_resp: TokenResponse = resp.json().await?;
                self.token = token_resp.token.or(token_resp.access_token);
            }
        }
        Ok(())
    }

    pub async fn fetch_manifest(&self, tag_or_digest: &str) -> Result<Manifest> {
        let url =
            format!("https://{}/v2/{}/manifests/{}", self.registry, self.repository, tag_or_digest);
        let mut req = self.client.get(&url).header(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json",
        );

        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await?;
        if resp.status().is_success() {
            let manifest: Manifest = resp.json().await?;
            Ok(manifest)
        } else {
            Err(OciError::ManifestNotFound)
        }
    }

    pub async fn fetch_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let url = format!("https://{}/v2/{}/blobs/{}", self.registry, self.repository, digest);
        let mut req = self.client.get(&url);

        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await?;
        if resp.status().is_success() {
            let bytes = resp.bytes().await?;
            Ok(bytes.to_vec())
        } else {
            Err(OciError::BlobNotFound(digest.to_string()))
        }
    }
}
