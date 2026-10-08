//! OSV (https://osv.dev): one `all.zip` of JSON records per ecosystem. Only the
//! language ecosystems come from here. Distro ecosystems come from the distros'
//! own trackers, which carry the backport-aware fixed versions.
use super::{download, step};
use crate::vuln::advisory::{cvss3_base, Advisory, Affected, Event, Range, Severity};
use crate::Result;
use anyhow::Context;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::io::{Read, Seek};

const ECOSYSTEMS: &[&str] = &["PyPI", "npm", "Go", "crates.io"];
/// Per-record cap while inflating, against zip bombs.
const MAX_RECORD: u64 = 32 << 20;

pub fn fetch(client: &Client) -> Result<Vec<(String, Vec<Advisory>)>> {
    ECOSYSTEMS
        .iter()
        .map(|eco| {
            let url = format!("https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip");
            let advisories = step(&format!("OSV {eco}"), || parse_zip(download(client, &url)?))?;
            Ok((format!("osv-{eco}"), advisories))
        })
        .collect()
}

fn parse_zip<R: Read + Seek>(r: R) -> Result<Vec<Advisory>> {
    let mut zip = zip::ZipArchive::new(r)?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        if !entry.name().ends_with(".json") {
            continue;
        }
        let mut buf = Vec::new();
        entry.take(MAX_RECORD + 1).read_to_end(&mut buf)?;
        anyhow::ensure!(
            buf.len() as u64 <= MAX_RECORD,
            "OSV record larger than {MAX_RECORD} bytes"
        );
        if let Some(a) = parse_record(&buf).with_context(|| format!("zip entry {i}"))? {
            out.push(a);
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

#[derive(Deserialize)]
struct Raw {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    withdrawn: Option<String>,
    #[serde(default)]
    severity: Vec<RawSeverity>,
    database_specific: Option<RawDbSpecific>,
    #[serde(default)]
    affected: Vec<RawAffected>,
}
#[derive(Deserialize)]
struct RawSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}
#[derive(Deserialize)]
struct RawDbSpecific {
    severity: Option<String>,
}
#[derive(Deserialize)]
struct RawAffected {
    package: Option<RawPackage>,
    #[serde(default)]
    ranges: Vec<RawRange>,
    #[serde(default)]
    versions: Vec<String>,
}
#[derive(Deserialize)]
struct RawPackage {
    ecosystem: String,
    name: String,
}
#[derive(Deserialize)]
struct RawRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<RawEvent>,
}
#[derive(Deserialize)]
struct RawEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

/// `None` for withdrawn records and records with nothing matchable.
fn parse_record(data: &[u8]) -> Result<Option<Advisory>> {
    let raw: Raw = serde_json::from_slice(data)?;
    if raw.withdrawn.is_some() {
        return Ok(None);
    }
    let affected: Vec<Affected> = raw
        .affected
        .into_iter()
        .filter_map(|a| {
            let p = a.package?;
            // GIT ranges are commit hashes; they cannot be compared to a package version.
            let ranges: Vec<Range> = a
                .ranges
                .into_iter()
                .filter(|r| r.kind != "GIT")
                .map(|r| Range {
                    kind: r.kind,
                    events: r
                        .events
                        .into_iter()
                        .map(|e| Event {
                            introduced: e.introduced,
                            fixed: e.fixed,
                            last_affected: e.last_affected,
                        })
                        .collect(),
                })
                .collect();
            (!ranges.is_empty() || !a.versions.is_empty()).then_some(Affected {
                ecosystem: p.ecosystem,
                name: p.name,
                ranges,
                versions: a.versions,
            })
        })
        .collect();
    if affected.is_empty() {
        return Ok(None);
    }
    let cvss =
        raw.severity.iter().filter(|s| s.kind == "CVSS_V3").find_map(|s| cvss3_base(&s.score));
    let severity = cvss.and_then(Severity::from_cvss).or_else(|| {
        raw.database_specific.and_then(|d| d.severity).and_then(|s| Severity::from_label(&s))
    });
    Ok(Some(Advisory { id: raw.id, aliases: raw.aliases, severity, cvss, affected }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ghsa_record() {
        let json = br#"{"id":"GHSA-xxxx","aliases":["CVE-2024-1"],
          "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
          "affected":[{"package":{"ecosystem":"PyPI","name":"requests","purl":"pkg:pypi/requests"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.32.0"}]},
                      {"type":"GIT","repo":"x","events":[{"introduced":"0"}]}]}]}"#;
        let a = parse_record(json).unwrap().unwrap();
        assert_eq!(a.severity, Some(Severity::Critical));
        assert_eq!(a.cvss, Some(9.8));
        assert_eq!(a.affected[0].ranges.len(), 1);
        assert_eq!(a.affected[0].ranges[0].events[1].fixed.as_deref(), Some("2.32.0"));
    }

    #[test]
    fn falls_back_to_label_and_skips_withdrawn() {
        let json = br#"{"id":"G","database_specific":{"severity":"MODERATE"},
          "affected":[{"package":{"ecosystem":"npm","name":"x"},"versions":["1.0.0"]}]}"#;
        assert_eq!(parse_record(json).unwrap().unwrap().severity, Some(Severity::Medium));
        assert!(parse_record(br#"{"id":"G","withdrawn":"2024-01-01T00:00:00Z","affected":[]}"#)
            .unwrap()
            .is_none());
    }
}
