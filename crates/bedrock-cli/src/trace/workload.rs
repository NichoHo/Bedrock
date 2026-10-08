//! The three ways to exercise the entrypoint while it is traced
//! (BEDROCK_SPEC.md 5.5): a script, an HTTP request list, or plain waiting.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum Workload {
    Script(std::path::PathBuf),
    Http(std::path::PathBuf),
    Duration(Duration),
}

impl Workload {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Script(_) => "script",
            Self::Http(_) => "http",
            Self::Duration(_) => "duration",
        }
    }
}

/// How to tell the entrypoint has finished starting.
#[derive(Debug, Clone, Default)]
pub struct Readiness {
    pub port: Option<u16>,
    /// Plain substring of the entrypoint's output (not a regex).
    pub log_pattern: Option<String>,
}

/// `30s`, `500ms`, `2m`, or a bare number of seconds.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let (num, unit) =
        s.split_at(s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len()));
    let n: f64 =
        num.parse().with_context(|| format!("invalid duration {s:?}, expected e.g. 30s"))?;
    let secs = match unit {
        "" | "s" => n,
        "ms" => n / 1000.0,
        "m" => n * 60.0,
        "h" => n * 3600.0,
        _ => bail!("invalid duration unit in {s:?}, expected ms, s, m or h"),
    };
    Ok(Duration::from_secs_f64(secs))
}

/// Polls until the TCP port accepts a connection.
pub fn wait_for_port(port: u16, timeout: Duration, give_up: impl Fn() -> bool) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline && !give_up() {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Parses a `.http` file: requests separated by `###`, each `METHOD target
/// [HTTP/x]`, optional `Header: value` lines, a blank line, then the body.
/// Lines starting with `#` or `//` are comments.
pub fn parse_http_file(text: &str) -> Result<Vec<HttpRequest>> {
    let mut out = Vec::new();
    for (i, block) in text.split("\n###").enumerate() {
        // Everything after `###` on its own line is a title.
        let block =
            if i == 0 { block } else { block.split_once('\n').map_or("", |(_, rest)| rest) };
        let mut lines = block.lines().map(|l| l.trim_end_matches('\r')).skip_while(|l| {
            let t = l.trim();
            t.is_empty() || t.starts_with('#') || t.starts_with("//")
        });
        let Some(first) = lines.next() else { continue };
        let mut parts = first.split_whitespace();
        let (method, target) = (parts.next().unwrap_or(""), parts.next());
        let Some(target) = target else { bail!("bad request line {first:?}") };
        if !method.chars().all(|c| c.is_ascii_uppercase()) {
            bail!("bad request line {first:?}");
        }
        let mut headers = Vec::new();
        let mut body = Vec::new();
        let mut in_body = false;
        for l in lines {
            if in_body {
                body.push(l);
            } else if l.trim().is_empty() {
                in_body = true;
            } else if let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        out.push(HttpRequest {
            method: method.into(),
            target: target.into(),
            headers,
            body: body.join("\n").trim_end().to_string(),
        });
    }
    if out.is_empty() {
        bail!("no requests in the .http file");
    }
    Ok(out)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResult {
    pub method: String,
    pub url: String,
    /// `None` when the request failed outright.
    pub status: Option<u16>,
    pub body_sha256: Option<String>,
}

/// Replays the requests against `127.0.0.1:port` (absolute URLs are used as is).
pub fn replay_http(requests: &[HttpRequest], port: u16) -> Vec<HttpResult> {
    use sha2::{Digest, Sha256};
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("client");
    requests
        .iter()
        .map(|r| {
            let url = if r.target.starts_with("http://") || r.target.starts_with("https://") {
                r.target.clone()
            } else {
                let sep = if r.target.starts_with('/') { "" } else { "/" };
                format!("http://127.0.0.1:{port}{sep}{}", r.target)
            };
            let method =
                reqwest::Method::from_bytes(r.method.as_bytes()).unwrap_or(reqwest::Method::GET);
            let mut req = client.request(method, &url);
            for (k, v) in &r.headers {
                req = req.header(k, v);
            }
            if !r.body.is_empty() {
                req = req.body(r.body.clone());
            }
            let (status, body_sha256) = match req.send() {
                Ok(mut resp) => {
                    let mut body = Vec::new();
                    let _ = resp.by_ref().take(64 << 20).read_to_end(&mut body);
                    (Some(resp.status().as_u16()), Some(hex::encode(Sha256::digest(&body))))
                }
                Err(_) => (None, None),
            };
            HttpResult { method: r.method.clone(), url, status, body_sha256 }
        })
        .collect()
}

/// Runs the user's script on the host. Its stdout goes to our stderr so the
/// reach set on stdout stays clean. Returns the exit code (`None` if killed by a signal).
pub fn run_script(script: &Path, port: Option<u16>) -> Result<Option<i32>> {
    let mut cmd = std::process::Command::new(script);
    cmd.stdout(std::process::Stdio::from(std::io::stderr()));
    if let Some(p) = port {
        cmd.env("BEDROCK_PORT", p.to_string());
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to run workload script {}", script.display()))?;
    Ok(status.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("7").unwrap(), Duration::from_secs(7));
        assert!(parse_duration("fast").is_err());
        assert!(parse_duration("5x").is_err());
    }

    #[test]
    fn http_file_parsing() {
        let t = "# health\nGET /healthz\n\n###\nPOST /items HTTP/1.1\nContent-Type: application/json\n\n{\"a\":1}\n\n### comment\nGET http://example.test/x\n";
        let r = parse_http_file(t).unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!((r[0].method.as_str(), r[0].target.as_str()), ("GET", "/healthz"));
        assert_eq!(r[1].headers, [("Content-Type".to_string(), "application/json".to_string())]);
        assert_eq!(r[1].body, "{\"a\":1}");
        assert!(parse_http_file("   \n").is_err());
        assert!(parse_http_file("get /x").is_err());
    }

    #[test]
    fn port_readiness() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(wait_for_port(port, Duration::from_secs(2), || false));
        drop(l);
        assert!(!wait_for_port(port, Duration::from_millis(300), || false));
    }
}
