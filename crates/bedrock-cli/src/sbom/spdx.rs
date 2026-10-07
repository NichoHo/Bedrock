use crate::sbom::{document_id, Sbom};
use serde_json::json;

pub fn write_spdx(sbom: &Sbom) -> String {
    let mut packages = Vec::new();
    let mut relationships = Vec::new();
    let mut describes = Vec::new();

    for (i, pkg) in sbom.packages.iter().enumerate() {
        // The index keeps IDs unique: names alone collide (two versions of one
        // npm package, or names that differ only in punctuation).
        let spdx_id = format!(
            "SPDXRef-Package-{}-{}",
            i,
            pkg.name.replace(|c: char| !c.is_ascii_alphanumeric(), "-")
        );

        packages.push(json!({
            "SPDXID": spdx_id,
            "name": pkg.name,
            "versionInfo": pkg.version,
            // Neither claimed nor derivable from a package DB entry alone.
            "downloadLocation": "NOASSERTION",
            // We record file *ownership* (which files a package owns) but don't
            // run per-file license/copyright analysis, so this must be false;
            // SPDX then requires omitting licenseInfoFromFiles and
            // packageVerificationCode, which we do.
            "filesAnalyzed": false,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": pkg.purl
                }
            ]
        }));

        // "This document describes this package" — SPDXRef-DOCUMENT is always
        // defined, unlike a made-up root-package id, so the relationship
        // target actually resolves.
        relationships.push(json!({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": spdx_id,
            "relationshipType": "DESCRIBES"
        }));
        describes.push(spdx_id);
    }

    let doc = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Bedrock-SBOM",
        // Must be unique per document (SPDX 2.3 section 2.5); a fixed string
        // reused across every SBOM Bedrock emits would violate that.
        "documentNamespace": format!("https://bedrock.example/spdxdocs/bedrock-sbom-{}", document_id()),
        "creationInfo": {
            "creators": ["Tool: Bedrock"],
            "created": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        },
        "documentDescribes": describes,
        "packages": packages,
        "relationships": relationships
    });

    serde_json::to_string_pretty(&doc).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom::Package;

    #[test]
    fn same_name_packages_get_distinct_spdx_ids() {
        let pkg = |v: &str| Package {
            name: "lru-cache".into(),
            version: v.into(),
            architecture: None,
            purl: format!("pkg:npm/lru-cache@{v}"),
            files: Vec::new(),
        };
        let out = write_spdx(&Sbom { packages: vec![pkg("7.0.0"), pkg("10.0.0")] });
        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        let ids: Vec<&str> = doc["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["SPDXID"].as_str().unwrap())
            .collect();
        assert_ne!(ids[0], ids[1]);
    }
}
