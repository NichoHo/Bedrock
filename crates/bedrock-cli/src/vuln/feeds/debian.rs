//! Debian security tracker (https://security-tracker.debian.org/tracker/data/json).
//! Keyed by *source* package, then CVE, then release. The per-release
//! `fixed_version` is the backport-aware one (`1.2.3-4+deb12u1`), which is why
//! this feed outranks OSV for Debian packages.
use super::get;
use crate::vuln::advisory::{Advisory, Affected, Range, Severity};
use crate::Result;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::io::Read;

const URL: &str = "https://security-tracker.debian.org/tracker/data/json";

pub fn fetch(client: &Client) -> Result<Vec<Advisory>> {
    parse(get(client, URL)?)
}

#[derive(Deserialize)]
struct Cve {
    #[serde(default)]
    releases: HashMap<String, Release>,
}
#[derive(Deserialize)]
struct Release {
    status: String,
    fixed_version: Option<String>,
    urgency: Option<String>,
}

/// `sid` and unknown codenames are skipped: nothing in an image reports them
/// as a numeric `VERSION_ID`.
fn release_number(codename: &str) -> Option<&'static str> {
    Some(match codename {
        "wheezy" => "7",
        "jessie" => "8",
        "stretch" => "9",
        "buster" => "10",
        "bullseye" => "11",
        "bookworm" => "12",
        "trixie" => "13",
        "forky" => "14",
        _ => return None,
    })
}

fn parse(r: impl Read) -> Result<Vec<Advisory>> {
    let tracker: HashMap<String, HashMap<String, Cve>> =
        serde_json::from_reader(std::io::BufReader::new(r))?;
    let mut out: BTreeMap<String, Advisory> = BTreeMap::new();
    for (pkg, cves) in tracker {
        for (id, cve) in cves {
            // TEMP-* ids are the tracker's pre-CVE placeholders.
            if !id.starts_with("CVE-") {
                continue;
            }
            for (codename, rel) in cve.releases {
                let Some(num) = release_number(&codename) else { continue };
                let fixed = match (rel.status.as_str(), rel.fixed_version.as_deref()) {
                    // "0" means the release was never affected.
                    ("resolved", Some("0")) => continue,
                    ("resolved", Some(v)) => Some(v),
                    ("open", _) => None,
                    _ => continue,
                };
                let adv = out.entry(id.clone()).or_insert_with(|| Advisory {
                    id: id.clone(),
                    aliases: vec![],
                    severity: None,
                    cvss: None,
                    affected: vec![],
                });
                adv.severity =
                    adv.severity.max(rel.urgency.as_deref().and_then(Severity::from_label));
                adv.affected.push(Affected {
                    ecosystem: format!("Debian:{num}"),
                    name: pkg.clone(),
                    ranges: vec![Range::up_to(fixed)],
                    versions: vec![],
                });
            }
        }
    }
    Ok(out.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_releases() {
        let json = r#"{"openssl":{
          "CVE-2024-1":{"description":"x","releases":{
            "bookworm":{"status":"resolved","fixed_version":"3.0.11-1~deb12u2","urgency":"high"},
            "bullseye":{"status":"open","urgency":"medium"},
            "trixie":{"status":"resolved","fixed_version":"0","urgency":"low"},
            "sid":{"status":"open","urgency":"low"}}},
          "TEMP-0000001-AAAA":{"releases":{"bookworm":{"status":"open"}}}}}"#;
        let a = parse(json.as_bytes()).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Some(Severity::High));
        let mut eco: Vec<_> = a[0].affected.iter().map(|x| x.ecosystem.as_str()).collect();
        eco.sort();
        assert_eq!(eco, ["Debian:11", "Debian:12"]);
        let bookworm = a[0].affected.iter().find(|x| x.ecosystem == "Debian:12").unwrap();
        assert_eq!(bookworm.ranges[0].events[1].fixed.as_deref(), Some("3.0.11-1~deb12u2"));
        let bullseye = a[0].affected.iter().find(|x| x.ecosystem == "Debian:11").unwrap();
        assert_eq!(bullseye.ranges[0].events.len(), 1); // open: no fix
    }
}
