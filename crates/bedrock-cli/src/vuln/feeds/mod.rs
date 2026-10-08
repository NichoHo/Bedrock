//! Fetchers for each advisory source. Each one turns its upstream format into
//! `Advisory` records; `update` is the only place that touches the network.
mod alpine;
mod debian;
mod osv;
mod redhat;

use super::advisory::Advisory;
use super::db::{Manifest, VulnerabilityDb};
use crate::Result;
use anyhow::{bail, Context};
use reqwest::blocking::Client;
use std::io::{Read, Seek, Write};
use std::time::Duration;

/// Hard cap on any single download, against a hostile or broken mirror.
const MAX_DOWNLOAD: u64 = 2 << 30;

fn client() -> Result<Client> {
    Ok(Client::builder()
        .user_agent(concat!("bedrock/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(900))
        .build()?)
}

fn get(client: &Client, url: &str) -> Result<reqwest::blocking::Response> {
    client.get(url).send().and_then(|r| r.error_for_status()).with_context(|| format!("GET {url}"))
}

/// Streams a URL to a temp file (the OSV zips need `Seek`), enforcing `MAX_DOWNLOAD`.
fn download(client: &Client, url: &str) -> Result<impl Read + Seek> {
    let resp = get(client, url)?;
    let mut file = tempfile::tempfile()?;
    let n = std::io::copy(&mut resp.take(MAX_DOWNLOAD + 1), &mut file)?;
    if n > MAX_DOWNLOAD {
        bail!("{url} exceeds the {MAX_DOWNLOAD} byte download limit");
    }
    file.flush()?;
    file.rewind()?;
    Ok(file)
}

/// Fetches every source and swaps the snapshot in. Any failure aborts before
/// the old snapshot is touched: a half-updated database is worse than a stale one.
pub fn update(db: &VulnerabilityDb) -> Result<Manifest> {
    let client = client()?;
    let mut sources: Vec<(String, Vec<Advisory>)> = osv::fetch(&client)?;
    sources.push(("debian".into(), step("Debian", || debian::fetch(&client))?));
    sources.push(("alpine".into(), step("Alpine", || alpine::fetch(&client))?));
    sources.push(("redhat".into(), step("Red Hat", || redhat::fetch(&client))?));
    db.replace(sources)
}

fn step(name: &str, f: impl FnOnce() -> Result<Vec<Advisory>>) -> Result<Vec<Advisory>> {
    eprintln!("fetching {name} ...");
    let v = f().with_context(|| format!("{name} feed"))?;
    eprintln!("  {} advisories", v.len());
    Ok(v)
}
