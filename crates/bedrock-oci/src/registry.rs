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
        let ping_url = format!("https://{}/v2/", self.registry);
        let resp = self.client.get(&ping_url).send().await?;
        
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            if let Some(auth_header) = resp.headers().get("Www-Authenticate") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if auth_str.starts_with("Bearer ") {
                        let params = auth_str.trim_start_matches("Bearer ");
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
                        
                        if !realm.is_empty() {
                            let mut auth_url = format!("{}?scope=repository:{}:pull", realm, self.repository);
                            if !service.is_empty() {
                                auth_url.push_str(&format!("&service={}", service));
                            }
                            
                            let token_resp = self.client.get(&auth_url).send().await?;
                            if token_resp.status().is_success() {
                                let tr: TokenResponse = token_resp.json().await?;
                                self.token = tr.token.or(tr.access_token);
                            }
                        }
                    }
                }
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
