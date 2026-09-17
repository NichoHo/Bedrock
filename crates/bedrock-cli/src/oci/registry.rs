use crate::oci::{Manifest, OciError}; use anyhow::Result;
use reqwest::blocking::Client;
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

    pub fn authenticate(&mut self) -> Result<()> {
        let ping_url = format!("https://{}/v2/", self.registry);
        let resp = self.client.get(&ping_url).send()?;
        
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
                            
                            let token_resp = self.client.get(&auth_url).send()?;
                            if token_resp.status().is_success() {
                                let tr: TokenResponse = token_resp.json()?;
                                self.token = tr.token.or(tr.access_token);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn fetch_manifest(&self, tag_or_digest: &str) -> Result<Manifest> {
        let url =
            format!("https://{}/v2/{}/manifests/{}", self.registry, self.repository, tag_or_digest);
        let mut req = self.client.get(&url).header(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json",
        );

        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let resp = req.send()?;
        if resp.status().is_success() {
            let manifest: Manifest = resp.json()?;
            Ok(manifest)
        } else {
            Err(OciError::ManifestNotFound.into())
        }
    }

    pub fn fetch_blob(&self, digest: &str, dest_path: &std::path::Path) -> Result<()> {
        let url = format!("https://{}/v2/{}/blobs/{}", self.registry, self.repository, digest);
        let mut req = self.client.get(&url);

        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let mut resp = req.send()?;
        if resp.status().is_success() {
            let digest_clean = digest.strip_prefix("sha256:").unwrap_or(digest);
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();

            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut file = std::fs::File::create(dest_path)?;
            let mut buf = [0; 8192];
            use std::io::{Read, Write};
            while let Ok(n) = resp.read(&mut buf) {
                if n == 0 { break; }
                hasher.update(&buf[..n]);
                file.write_all(&buf[..n])?;
            }

            let hash = hex::encode(hasher.finalize());
            if hash != digest_clean {
                let _ = std::fs::remove_file(dest_path);
                return Err(anyhow::anyhow!(crate::oci::OciError::InvalidDigest(format!("Digest mismatch: expected {}, got {}", digest_clean, hash))));
            }

            Ok(())
        } else {
            Err(OciError::BlobNotFound(digest.to_string()).into())
        }
    }
}







