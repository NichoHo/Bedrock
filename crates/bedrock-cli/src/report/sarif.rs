//! SARIF 2.1.0 rendering, shaped for GitHub code scanning: one rule per
//! vulnerability id, one result per affected package. An image has no source
//! file, so the artifact location is the image reference and the package PURL
//! rides along as a logical location.
use super::Report;
use crate::vuln::Severity;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn to_sarif(report: &Report) -> String {
    let mut rules: BTreeMap<&str, Value> = BTreeMap::new();
    let mut results = Vec::new();
    for f in &report.findings {
        let (level, fallback_score) = match f.severity {
            Some(Severity::Critical) => ("error", 9.5),
            Some(Severity::High) => ("error", 8.0),
            Some(Severity::Medium) => ("warning", 5.5),
            Some(Severity::Low) | None => ("note", 2.0),
        };
        rules.entry(&f.id).or_insert_with(|| {
            json!({
                "id": f.id,
                "name": f.id,
                "shortDescription": { "text": f.id },
                "helpUri": help_uri(&f.id),
                // GitHub buckets alerts by this 0-10 score.
                "properties": { "security-severity": format!("{:.1}", f.cvss.unwrap_or(fallback_score)) },
            })
        });
        let fix = match (&f.fixed_version, &f.fixed_package) {
            (Some(v), Some(p)) => format!(" Fixed in {p} {v}."),
            (Some(v), None) => format!(" Fixed in {v}."),
            _ => " No fix available.".into(),
        };
        let fingerprint = hex::encode(Sha256::digest(format!("{}|{}", f.id, f.package.purl)));
        results.push(json!({
            "ruleId": f.id,
            "level": level,
            "message": { "text": format!("{} {} is affected by {}.{fix}", f.package.name, f.package.version, f.id) },
            "locations": [{
                "physicalLocation": { "artifactLocation": { "uri": report.input.reference } },
                "logicalLocations": [{ "name": f.package.purl, "kind": "package" }],
            }],
            "partialFingerprints": { "bedrock/finding/v1": fingerprint },
        }));
    }
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "bedrock",
                "version": report.tool_version,
                "informationUri": "https://github.com/NichoHo/Bedrock",
                "rules": rules.into_values().collect::<Vec<_>>(),
            }},
            "results": results,
        }],
    });
    serde_json::to_string_pretty(&doc).expect("sarif serialises")
}

fn help_uri(id: &str) -> String {
    match id {
        i if i.starts_with("CVE-") => format!("https://nvd.nist.gov/vuln/detail/{i}"),
        i if i.starts_with("GHSA-") => format!("https://github.com/advisories/{i}"),
        i => format!("https://osv.dev/vulnerability/{i}"),
    }
}
