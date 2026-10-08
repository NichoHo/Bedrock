//! Alpine secdb (https://secdb.alpinelinux.org). Per release and repo, a
//! `secfixes` map of "version that fixed it" to CVE ids, keyed by *origin*
//! package (the apk database's `o:` field), not by subpackage name.
use super::get;
use crate::vuln::advisory::{Advisory, Affected, Range};
use crate::Result;
use anyhow::Context;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

const BASE: &str = "https://secdb.alpinelinux.org";

pub fn fetch(client: &Client) -> Result<Vec<Advisory>> {
    let index = get(client, &format!("{BASE}/"))?.text()?;
    let mut docs = Vec::new();
    for release in releases(&index) {
        for repo in ["main", "community"] {
            let url = format!("{BASE}/{release}/{repo}.json");
            let resp = client.get(&url).send().with_context(|| format!("GET {url}"))?;
            // Old releases have no community repo.
            if resp.status() == StatusCode::NOT_FOUND {
                continue;
            }
            let doc: Doc = resp.error_for_status()?.json().with_context(|| url.clone())?;
            docs.push(doc);
        }
    }
    Ok(normalise(docs))
}

/// `v3.20/` links from the directory listing. `edge` is a rolling target with
/// no stable version to match, so it is skipped.
fn releases(index: &str) -> Vec<String> {
    index
        .split("href=\"")
        .skip(1)
        .filter_map(|s| s.split_once("/\"").map(|(h, _)| h))
        .filter(|h| h.starts_with('v') && h[1..].chars().all(|c| c.is_ascii_digit() || c == '.'))
        .map(String::from)
        .collect()
}

#[derive(Deserialize)]
struct Doc {
    distroversion: String,
    #[serde(default)]
    packages: Vec<Entry>,
}
#[derive(Deserialize)]
struct Entry {
    pkg: Pkg,
}
#[derive(Deserialize)]
struct Pkg {
    name: String,
    #[serde(default)]
    secfixes: HashMap<String, Vec<String>>,
}

fn normalise(docs: Vec<Doc>) -> Vec<Advisory> {
    let mut out: BTreeMap<String, Advisory> = BTreeMap::new();
    for doc in docs {
        let ecosystem = format!("Alpine:{}", doc.distroversion);
        for Entry { pkg } in doc.packages {
            for (fixed, ids) in pkg.secfixes {
                // "0" lists CVEs that never affected the package.
                if fixed == "0" {
                    continue;
                }
                for raw in ids {
                    // Entries are "CVE-2024-1234" optionally followed by a tracker note.
                    let Some(id) = raw.split_whitespace().next().filter(|i| i.starts_with("CVE-"))
                    else {
                        continue;
                    };
                    let adv = out.entry(id.to_string()).or_insert_with(|| Advisory {
                        id: id.to_string(),
                        aliases: vec![],
                        severity: None,
                        cvss: None,
                        affected: vec![],
                    });
                    // ponytail: one entry per (release, package, fix). A CVE fixed twice in
                    // one package yields two ranges, so versions under the later fix match.
                    adv.affected.push(Affected {
                        ecosystem: ecosystem.clone(),
                        name: pkg.name.clone(),
                        ranges: vec![Range::up_to(Some(&fixed))],
                        versions: vec![],
                    });
                }
            }
        }
    }
    out.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_release_dirs() {
        let html = r#"<a href="../">../</a><a href="edge/">edge/</a><a href="v3.2/">v3.2/</a><a href="v3.20/">v3.20/</a><a href="last-update">x</a>"#;
        assert_eq!(releases(html), ["v3.2", "v3.20"]);
    }

    #[test]
    fn groups_by_cve() {
        let doc: Doc = serde_json::from_str(
            r#"{"distroversion":"v3.20","packages":[
              {"pkg":{"name":"apache2","secfixes":{"2.4.55-r0":["CVE-2006-20001","XSA-1"],"0":["CVE-2000-0"]}}},
              {"pkg":{"name":"curl","secfixes":{"8.0.0-r0":["CVE-2006-20001 note"]}}}]}"#,
        )
        .unwrap();
        let a = normalise(vec![doc]);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].id, "CVE-2006-20001");
        assert_eq!(a[0].affected.len(), 2);
        assert_eq!(a[0].affected[0].ecosystem, "Alpine:v3.20");
    }
}
