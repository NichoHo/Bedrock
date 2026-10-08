//! Registry credentials from the standard Docker config (`config.json`).
//!
//! Bedrock never stores a credential: each run reads whatever Docker's own
//! config or credential helper provides, and nothing is written back.
use base64::Engine;
use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Deliberately not `Debug`, so a stray `{:?}` can't print the password.
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Where Docker keeps its config: `$DOCKER_CONFIG/config.json`, else `~/.docker/config.json`.
fn config_path() -> Option<PathBuf> {
    let dir = std::env::var_os("DOCKER_CONFIG")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".docker")))?;
    Some(dir.join("config.json"))
}

/// Credentials for `registry`, or `None` for anonymous access. A missing
/// config file is normal; a broken credential helper is reported on stderr
/// and falls back to anonymous (which then fails with the registry's own 401
/// if the image is private).
pub fn lookup(registry: &str) -> Option<Credentials> {
    let text = std::fs::read_to_string(config_path()?).ok()?;
    let config: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Warning: ignoring unreadable Docker config: {e}");
            return None;
        }
    };
    lookup_in(&config, registry, run_helper)
}

/// Names Docker config files use for a registry. Docker Hub is the odd one:
/// it is stored under its legacy index URL.
fn config_keys(registry: &str) -> Vec<String> {
    if registry == "registry-1.docker.io" || registry == "docker.io" {
        ["https://index.docker.io/v1/", "index.docker.io", "docker.io", "registry-1.docker.io"]
            .map(String::from)
            .to_vec()
    } else {
        vec![registry.to_string(), format!("https://{registry}")]
    }
}

fn lookup_in(
    config: &Value,
    registry: &str,
    helper: impl Fn(&str, &str) -> anyhow::Result<Option<Credentials>>,
) -> Option<Credentials> {
    for key in config_keys(registry) {
        // Inline `auth` is base64("user:password").
        if let Some(c) = config["auths"][&key]["auth"].as_str().and_then(decode_auth) {
            return Some(c);
        }
        let helper_name =
            config["credHelpers"][&key].as_str().or_else(|| config["credsStore"].as_str());
        if let Some(name) = helper_name {
            match helper(name, &key) {
                Ok(Some(c)) => return Some(c),
                Ok(None) => {}
                Err(e) => eprintln!("Warning: docker-credential-{name} failed for {key}: {e:#}"),
            }
        }
    }
    None
}

fn decode_auth(auth: &str) -> Option<Credentials> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(auth.trim()).ok()?;
    let (username, password) = String::from_utf8(bytes)
        .ok()?
        .split_once(':')
        .map(|(u, p)| (u.to_string(), p.to_string()))?;
    Some(Credentials { username, password })
}

/// Runs `docker-credential-<name> get` per the credential-helper protocol:
/// server URL on stdin, `{"Username":..,"Secret":..}` on stdout.
fn run_helper(name: &str, server: &str) -> anyhow::Result<Option<Credentials>> {
    let mut child = Command::new(format!("docker-credential-{name}"))
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child.stdin.take().expect("stdin is piped").write_all(server.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        // Helpers exit non-zero with "credentials not found" when they simply
        // have nothing for this server. That is not an error.
        let msg = String::from_utf8_lossy(&out.stdout);
        if msg.contains("credentials not found") {
            return Ok(None);
        }
        anyhow::bail!("exited with {}: {}", out.status, msg.trim());
    }
    let v: Value = serde_json::from_slice(&out.stdout)?;
    let (user, secret) = (v["Username"].as_str().unwrap_or(""), v["Secret"].as_str().unwrap_or(""));
    if user == "<token>" {
        anyhow::bail!("identity tokens (OAuth refresh tokens) are not supported");
    }
    Ok((!secret.is_empty()).then(|| Credentials { username: user.into(), password: secret.into() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn no_helper(_: &str, _: &str) -> anyhow::Result<Option<Credentials>> {
        panic!("helper must not run")
    }

    #[test]
    fn inline_auth_is_decoded() {
        // base64("alice:s3cret:with:colons")
        let cfg = json!({"auths": {"ghcr.io": {"auth": "YWxpY2U6czNjcmV0OndpdGg6Y29sb25z"}}});
        let c = lookup_in(&cfg, "ghcr.io", no_helper).unwrap();
        assert_eq!((c.username.as_str(), c.password.as_str()), ("alice", "s3cret:with:colons"));
    }

    #[test]
    fn cred_helper_beats_cred_store_and_receives_the_config_key() {
        let cfg = json!({"credsStore": "desktop", "credHelpers": {"ghcr.io": "pass"}});
        let helper = |name: &str, server: &str| {
            assert_eq!((name, server), ("pass", "ghcr.io"));
            Ok(Some(Credentials { username: "u".into(), password: "p".into() }))
        };
        assert!(lookup_in(&cfg, "ghcr.io", helper).is_some());
    }

    #[test]
    fn docker_hub_uses_its_legacy_key() {
        let cfg = json!({"credsStore": "desktop"});
        let helper = |_: &str, server: &str| {
            Ok((server == "https://index.docker.io/v1/")
                .then(|| Credentials { username: "u".into(), password: "p".into() }))
        };
        assert!(lookup_in(&cfg, "registry-1.docker.io", helper).is_some());
    }

    #[test]
    fn no_config_entry_means_anonymous() {
        assert!(lookup_in(&json!({"auths": {"ghcr.io": {}}}), "ghcr.io", no_helper).is_none());
    }
}
