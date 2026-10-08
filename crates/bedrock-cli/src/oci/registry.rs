use crate::oci::auth::{self, Credentials};
use crate::oci::manifest::{resolve_manifest, verify_digest};
use crate::oci::{Manifest, OciError};
use anyhow::{Context, Result};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{AUTHORIZATION, RETRY_AFTER};
use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;

/// How many times one request is tried when the registry rate-limits it.
const MAX_ATTEMPTS: u32 = 5;
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How long to wait before retry number `attempt` (0-based): the server's
/// `Retry-After` seconds if it sent them, else 1s, 2s, 4s, 8s. Capped, so a
/// hostile registry can't stall the tool for hours.
fn retry_delay(attempt: u32, retry_after: Option<&str>) -> Duration {
    retry_after
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(1 << attempt.min(6)))
        .min(MAX_BACKOFF)
}

/// Sends the request `build` makes, retrying on 429/503 with backoff. Takes a
/// builder function because a `RequestBuilder` is consumed by `send`.
fn send_with_retry(build: impl Fn() -> RequestBuilder) -> Result<Response> {
    for attempt in 0.. {
        let resp = build().send()?;
        let throttled = matches!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
        );
        if !throttled || attempt + 1 >= MAX_ATTEMPTS {
            return Ok(resp);
        }
        let hdr = resp.headers().get(RETRY_AFTER).and_then(|v| v.to_str().ok());
        let delay = retry_delay(attempt, hdr);
        eprintln!("Registry returned {}; retrying in {}s", resp.status(), delay.as_secs());
        std::thread::sleep(delay);
    }
    unreachable!("loop returns on the last attempt")
}

const MANIFEST_ACCEPT: &str = "application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.index.v1+json";

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

/// `http` for a loopback registry (local testing), `https` for everything else.
fn scheme_for(registry: &str) -> &'static str {
    let host = registry
        .rsplit_once(':')
        .filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit()))
        .map_or(registry, |(h, _)| h);
    if matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
        "http"
    } else {
        "https"
    }
}

pub struct RegistryClient {
    client: Client,
    scheme: &'static str,
    registry: String,
    repository: String,
    /// Full `Authorization` header value once authenticated.
    authorization: Option<String>,
}

impl RegistryClient {
    pub fn new(registry: &str, repository: &str) -> Self {
        Self {
            // reqwest's blocking default is a 30s deadline for the whole
            // response, body included, which would abort any big layer.
            client: Client::builder()
                .timeout(None)
                .connect_timeout(Duration::from_secs(30))
                .build()
                .expect("static client config is valid"),
            scheme: scheme_for(registry),
            registry: registry.to_string(),
            repository: repository.to_string(),
            authorization: None,
        }
    }

    pub fn authenticate(&mut self) -> Result<()> {
        self.authenticate_for("pull")
    }

    /// Like [`authenticate`](Self::authenticate), with permission to write.
    pub fn authenticate_push(&mut self) -> Result<()> {
        self.authenticate_for("pull,push")
    }

    fn authenticate_for(&mut self, actions: &str) -> Result<()> {
        let ping_url = format!("{}://{}/v2/", self.scheme, self.registry);
        let resp =
            send_with_retry(|| self.client.get(&ping_url)).context("registry ping failed")?;

        if resp.status() != StatusCode::UNAUTHORIZED {
            return Ok(());
        }

        let auth_header = resp
            .headers()
            .get("Www-Authenticate")
            .context("registry returned 401 with no Www-Authenticate challenge")?;
        let auth_str = auth_header.to_str().context("non-UTF8 Www-Authenticate header")?;
        // Only read Docker's credential store once a registry actually asks.
        let creds = auth::lookup(&self.registry);

        if auth_str.len() >= 6 && auth_str[..6].eq_ignore_ascii_case("basic ") {
            let c = creds.with_context(|| {
                format!(
                    "{} requires credentials; run `docker login {}`",
                    self.registry, self.registry
                )
            })?;
            self.authorization = Some(basic_header(&c));
            return Ok(());
        }
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
        // The realm comes from the registry's response; never send a password
        // to it in cleartext.
        if creds.is_some() && !realm.starts_with("https://") {
            anyhow::bail!("refusing to send credentials to non-HTTPS token endpoint {realm}");
        }

        let mut auth_url = format!("{}?scope=repository:{}:{}", realm, self.repository, actions);
        if !service.is_empty() {
            auth_url.push_str(&format!("&service={}", service));
        }

        let token_resp = send_with_retry(|| {
            let req = self.client.get(&auth_url);
            match &creds {
                Some(c) => req.basic_auth(&c.username, Some(&c.password)),
                None => req,
            }
        })
        .context("token endpoint request failed")?;
        if !token_resp.status().is_success() {
            let hint = if creds.is_none() && token_resp.status() == StatusCode::UNAUTHORIZED {
                format!(" (no credentials found; try `docker login {}`)", self.registry)
            } else {
                String::new()
            };
            anyhow::bail!("token endpoint returned {}{hint}", token_resp.status());
        }
        let tr: TokenResponse =
            token_resp.json().context("token endpoint returned invalid JSON")?;
        let token = tr
            .token
            .or(tr.access_token)
            .context("token endpoint response had neither `token` nor `access_token`")?;
        self.authorization = Some(format!("Bearer {token}"));
        Ok(())
    }

    fn get(&self, url: &str) -> RequestBuilder {
        let req = self.client.get(url);
        match &self.authorization {
            Some(a) => req.header(AUTHORIZATION, a),
            None => req,
        }
    }

    fn fetch_manifest_bytes(&self, tag_or_digest: &str) -> Result<Vec<u8>> {
        let url = format!(
            "{}://{}/v2/{}/manifests/{}",
            self.scheme, self.registry, self.repository, tag_or_digest
        );
        let resp = send_with_retry(|| self.get(&url).header("Accept", MANIFEST_ACCEPT))
            .context("manifest request failed")?;
        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Err(OciError::ManifestNotFound.into());
        }
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            anyhow::bail!("registry returned {status} fetching manifest {tag_or_digest}: {body}");
        }
        let bytes = resp.bytes().context("failed to read manifest response body")?.to_vec();
        // A tag is mutable, so there's nothing to check it against; a digest
        // (user-pinned, or an index entry) must match what came back.
        if tag_or_digest.contains(':') {
            verify_digest(&bytes, tag_or_digest)
                .with_context(|| format!("manifest {tag_or_digest} failed verification"))?;
        }
        Ok(bytes)
    }

    /// Fetches the manifest for `tag_or_digest` and resolves it (following an
    /// index/manifest-list if the registry returns one) to the manifest for
    /// `os`/`arch`.
    pub fn resolve_manifest(&self, tag_or_digest: &str, os: &str, arch: &str) -> Result<Manifest> {
        let data = self.fetch_manifest_bytes(tag_or_digest)?;
        resolve_manifest(&data, os, arch, |digest| self.fetch_manifest_bytes(digest))
    }

    pub fn fetch_blob(&self, digest: &str, dest_path: &std::path::Path) -> Result<()> {
        let url =
            format!("{}://{}/v2/{}/blobs/{}", self.scheme, self.registry, self.repository, digest);
        let mut resp = send_with_retry(|| self.get(&url)).context("blob request failed")?;
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

        // Download to a temp name and rename only after the digest checks out:
        // the cache treats "file exists at the digest path" as "blob is good",
        // so a partial write there (killed mid-download) would stick forever.
        let partial = dest_path.with_extension(format!("{}.partial", std::process::id()));
        let mut file = std::fs::File::create(&partial)?;
        let mut buf = [0; 8192];
        use std::io::{Read, Write};
        loop {
            let n = match resp.read(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    let _ = std::fs::remove_file(&partial);
                    return Err(e).context("error reading blob response body");
                }
            };
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])?;
        }
        drop(file);

        let hash = hex::encode(hasher.finalize());
        if hash != digest_clean {
            let _ = std::fs::remove_file(&partial);
            return Err(anyhow::anyhow!(OciError::InvalidDigest(format!(
                "Digest mismatch: expected {}, got {}",
                digest_clean, hash
            ))));
        }

        std::fs::rename(&partial, dest_path)?;
        Ok(())
    }
}

impl RegistryClient {
    fn authed(&self, req: RequestBuilder) -> RequestBuilder {
        match &self.authorization {
            Some(a) => req.header(AUTHORIZATION, a),
            None => req,
        }
    }

    fn repo_url(&self, tail: &str) -> String {
        format!("{}://{}/v2/{}/{}", self.scheme, self.registry, self.repository, tail)
    }

    pub fn blob_exists(&self, digest: &str) -> Result<bool> {
        let url = self.repo_url(&format!("blobs/{digest}"));
        let resp =
            send_with_retry(|| self.authed(self.client.head(&url))).context("blob check failed")?;
        Ok(resp.status().is_success())
    }

    /// Uploads a blob (monolithic upload) unless the registry already has it.
    pub fn push_blob(&self, digest: &str, data: &[u8]) -> Result<()> {
        if self.blob_exists(digest)? {
            return Ok(());
        }
        let start_url = self.repo_url("blobs/uploads/");
        let start = send_with_retry(|| self.authed(self.client.post(&start_url)))
            .context("blob upload could not start")?;
        if start.status() != StatusCode::ACCEPTED {
            anyhow::bail!(
                "registry returned {} starting a blob upload (is the token allowed to push?)",
                start.status()
            );
        }
        let location = start
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .context("upload response had no Location")?
            .to_string();
        let location = if location.starts_with('/') {
            format!("{}://{}{}", self.scheme, self.registry, location)
        } else {
            location
        };
        let url =
            format!("{location}{}digest={digest}", if location.contains('?') { '&' } else { '?' });
        let put = send_with_retry(|| {
            self.authed(
                self.client
                    .put(&url)
                    .header("Content-Type", "application/octet-stream")
                    .body(data.to_vec()),
            )
        })
        .context("blob upload failed")?;
        if !put.status().is_success() {
            anyhow::bail!("registry returned {} uploading blob {digest}", put.status());
        }
        Ok(())
    }

    /// Pushes a manifest under `reference` (tag or digest). Returns whether the
    /// registry indexed its `subject` itself (the `OCI-Subject` response header).
    pub fn push_manifest(&self, reference: &str, media_type: &str, data: &[u8]) -> Result<bool> {
        let url = self.repo_url(&format!("manifests/{reference}"));
        let resp = send_with_retry(|| {
            self.authed(
                self.client.put(&url).header("Content-Type", media_type).body(data.to_vec()),
            )
        })
        .context("manifest upload failed")?;
        if !resp.status().is_success() {
            let body = resp.text().unwrap_or_default();
            anyhow::bail!("registry rejected manifest {reference}: {body}");
        }
        Ok(resp.headers().contains_key("OCI-Subject"))
    }

    /// A manifest's raw bytes and media type, or `None` if it does not exist.
    pub fn manifest_raw(&self, reference: &str) -> Result<Option<(Vec<u8>, String)>> {
        let url = self.repo_url(&format!("manifests/{reference}"));
        let resp = send_with_retry(|| {
            self.authed(self.client.get(&url).header("Accept", MANIFEST_ACCEPT))
        })
        .context("manifest request failed")?;
        match resp.status() {
            StatusCode::NOT_FOUND => Ok(None),
            s if s.is_success() => {
                let mt = resp
                    .headers()
                    .get("Content-Type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                Ok(Some((resp.bytes()?.to_vec(), mt)))
            }
            s => anyhow::bail!("registry returned {s} fetching manifest {reference}"),
        }
    }
}

fn basic_header(c: &Credentials) -> String {
    use base64::Engine;
    let raw = format!("{}:{}", c.username, c.password);
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_registries_use_plain_http() {
        assert_eq!(scheme_for("localhost:5000"), "http");
        assert_eq!(scheme_for("127.0.0.1:5055"), "http");
        assert_eq!(scheme_for("localhost"), "http");
        assert_eq!(scheme_for("registry-1.docker.io"), "https");
        assert_eq!(scheme_for("ghcr.io"), "https");
        assert_eq!(scheme_for("localhost.evil.com:443"), "https");
    }

    #[test]
    fn backoff_honours_retry_after_and_is_capped() {
        assert_eq!(retry_delay(0, None), Duration::from_secs(1));
        assert_eq!(retry_delay(3, None), Duration::from_secs(8));
        assert_eq!(retry_delay(0, Some("7")), Duration::from_secs(7));
        assert_eq!(retry_delay(0, Some("86400")), MAX_BACKOFF);
        // An HTTP-date Retry-After isn't parsed; fall back to exponential.
        assert_eq!(retry_delay(1, Some("Wed, 21 Oct 2026 07:28:00 GMT")), Duration::from_secs(2));
    }
}
