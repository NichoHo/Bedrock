//! Red Hat Security Data API (https://access.redhat.com/hydra/rest/securitydata).
//! `affected_packages` lists the *fixed* NEVRAs, one per product stream. The
//! `.elN` tag in the release picks the major, so a package is vulnerable on
//! major N when it is older than a fix carrying that tag.
use super::get;
use crate::vuln::advisory::{Advisory, Affected, Range, Severity};
use crate::Result;
use anyhow::Context;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::BTreeMap;

const URL: &str = "https://access.redhat.com/hydra/rest/securitydata/cve.json";
const PAGE: usize = 1000;
/// Safety stop; the full catalogue is a few dozen pages.
const MAX_PAGES: usize = 500;

pub fn fetch(client: &Client) -> Result<Vec<Advisory>> {
    let mut all = Vec::new();
    for page in 1..=MAX_PAGES {
        let url = format!("{URL}?per_page={PAGE}&page={page}&after=1999-01-01");
        let batch: Vec<Cve> = get(client, &url)?.json().with_context(|| format!("page {page}"))?;
        let n = batch.len();
        all.extend(batch);
        if n < PAGE {
            return Ok(normalise(all));
        }
    }
    anyhow::bail!("Red Hat API returned more than {MAX_PAGES} pages")
}

#[derive(Deserialize)]
struct Cve {
    #[serde(rename = "CVE")]
    id: String,
    severity: Option<String>,
    cvss3_score: Option<String>,
    affected_packages: Option<Vec<String>>,
}

/// `kernel-0:4.18.0-193.el8_2` -> (`kernel`, `0:4.18.0-193.el8_2`, `8`).
/// Module streams (`go-toolset:rhel8-...`) and bare names have no numeric
/// epoch and are skipped.
fn parse_nevra(s: &str) -> Option<(&str, &str, &str)> {
    let colon = s.find(':')?;
    let dash = s[..colon].rfind('-')?;
    let (name, evr) = (&s[..dash], &s[dash + 1..]);
    if !s[dash + 1..colon].bytes().all(|b| b.is_ascii_digit()) || colon == dash + 1 {
        return None;
    }
    let i = evr.find(".el")? + 3;
    let digits = evr[i..].bytes().take_while(u8::is_ascii_digit).count();
    (digits > 0).then_some((name, evr, &evr[i..i + digits]))
}

fn normalise(cves: Vec<Cve>) -> Vec<Advisory> {
    let mut out: BTreeMap<String, Advisory> = BTreeMap::new();
    for cve in cves {
        // (ecosystem, package) -> fixed EVRs
        let mut groups: BTreeMap<(String, &str), Vec<&str>> = BTreeMap::new();
        for p in cve.affected_packages.iter().flatten() {
            if let Some((name, evr, major)) = parse_nevra(p) {
                groups.entry((format!("Red Hat:{major}"), name)).or_default().push(evr);
            }
        }
        if groups.is_empty() {
            continue;
        }
        let cvss = cve.cvss3_score.as_deref().and_then(|s| s.parse::<f32>().ok());
        let severity = cvss
            .and_then(Severity::from_cvss)
            .or_else(|| cve.severity.as_deref().and_then(Severity::from_label));
        let affected = groups
            .into_iter()
            .map(|((ecosystem, name), evrs)| Affected {
                ecosystem,
                name: name.to_string(),
                // Ranges are a union: vulnerable below the highest fix across streams.
                ranges: evrs.into_iter().map(|e| Range::up_to(Some(e))).collect(),
                versions: vec![],
            })
            .collect();
        out.insert(
            cve.id.clone(),
            Advisory { id: cve.id, aliases: vec![], severity, cvss, affected },
        );
    }
    out.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nevra_parsing() {
        assert_eq!(
            parse_nevra("kernel-0:4.18.0-193.128.1.el8_2"),
            Some(("kernel", "0:4.18.0-193.128.1.el8_2", "8"))
        );
        assert_eq!(
            parse_nevra("kernel-rt-0:5.14.0-70.93.1.rt21.165.el9_0").unwrap().0,
            "kernel-rt"
        );
        assert_eq!(parse_nevra("go-toolset:rhel8-8080020230627164522.6b4b45d8"), None);
        assert_eq!(parse_nevra("kpatch-patch"), None);
    }

    #[test]
    fn groups_and_rates() {
        let cves: Vec<Cve> = serde_json::from_str(
            r#"[{"CVE":"CVE-2023-3390","severity":"important","cvss3_score":"7.8",
              "affected_packages":["kernel-0:4.18.0-477.27.1.el8_8","kernel-0:5.14.0-284.30.1.el9_2","kpatch-patch"]},
              {"CVE":"CVE-2023-1","severity":"low","cvss3_score":null,"affected_packages":[]}]"#,
        )
        .unwrap();
        let a = normalise(cves);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Some(Severity::High));
        let eco: Vec<_> = a[0].affected.iter().map(|x| x.ecosystem.as_str()).collect();
        assert_eq!(eco, ["Red Hat:8", "Red Hat:9"]);
    }
}
