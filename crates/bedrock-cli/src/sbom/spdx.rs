use crate::sbom::{document_id, Sbom};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;

/// SPDX 2.3 section 7.9: the SHA-1 of the package's file SHA-1s, as sorted
/// lowercase hex strings concatenated with no separator.
fn verification_code(sbom: &Sbom, files: &[std::path::PathBuf]) -> String {
    use sha1::{Digest, Sha1};
    let mut hashes: Vec<String> = files
        .iter()
        .filter_map(|f| sbom.file_digests.get(f))
        .map(|d| hex::encode(d.sha1))
        .collect();
    hashes.sort();
    hex::encode(Sha1::digest(hashes.concat()))
}

pub fn write_spdx(sbom: &Sbom) -> String {
    let mut packages = Vec::new();
    let mut relationships = Vec::new();
    let mut describes = Vec::new();

    // One File element per distinct path: a path owned by two packages (dpkg
    // diversions, say) gets one ID and two CONTAINS relationships, since
    // duplicate SPDXIDs make the document invalid.
    let file_ids: BTreeMap<&Path, String> = sbom
        .file_digests
        .keys()
        .enumerate()
        .map(|(i, path)| (path.as_path(), format!("SPDXRef-File-{i}")))
        .collect();

    for (i, pkg) in sbom.packages.iter().enumerate() {
        // The index keeps IDs unique: names alone collide (two versions of one
        // npm package, or names that differ only in punctuation).
        let spdx_id = format!(
            "SPDXRef-Package-{}-{}",
            i,
            pkg.name.replace(|c: char| !c.is_ascii_alphanumeric(), "-")
        );

        let mut package = json!({
            "SPDXID": spdx_id,
            "name": pkg.name,
            "versionInfo": pkg.version,
            // Neither claimed nor derivable from a package DB entry alone.
            "downloadLocation": "NOASSERTION",
            // SPDX only allows CONTAINS relationships from a package whose
            // files were analyzed, and then requires a verification code.
            // Packages with no files in the image say false and list none.
            "filesAnalyzed": !pkg.files.is_empty(),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": pkg.purl
                }
            ]
        });
        if !pkg.files.is_empty() {
            package["packageVerificationCode"] =
                json!({ "packageVerificationCodeValue": verification_code(sbom, &pkg.files) });
        }
        packages.push(package);

        // "This document describes this package" — SPDXRef-DOCUMENT is always
        // defined, unlike a made-up root-package id, so the relationship
        // target actually resolves.
        relationships.push(json!({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": spdx_id,
            "relationshipType": "DESCRIBES"
        }));
        for file in &pkg.files {
            if let Some(file_id) = file_ids.get(file.as_path()) {
                relationships.push(json!({
                    "spdxElementId": spdx_id,
                    "relatedSpdxElement": file_id,
                    "relationshipType": "CONTAINS"
                }));
            }
        }
        describes.push(spdx_id);
    }

    let files: Vec<_> = sbom
        .file_digests
        .iter()
        .map(|(path, d)| {
            json!({
                "SPDXID": file_ids[path.as_path()],
                // SPDX file names are relative paths prefixed with "./".
                "fileName": format!("./{}", path.display()),
                "checksums": [
                    { "algorithm": "SHA1", "checksumValue": hex::encode(d.sha1) },
                    { "algorithm": "SHA256", "checksumValue": hex::encode(d.sha256) }
                ]
            })
        })
        .collect();

    let doc = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Bedrock-SBOM",
        // Must be unique per document (SPDX 2.3 section 2.5); a fixed string
        // reused across every SBOM Bedrock emits would violate that.
        "documentNamespace": format!("https://bedrock.example/spdxdocs/bedrock-sbom-{}", document_id()),
        "creationInfo": {
            "creators": [format!("Tool: bedrock-{}", env!("CARGO_PKG_VERSION"))],
            "created": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        },
        "documentDescribes": describes,
        "packages": packages,
        "files": files,
        "relationships": relationships
    });

    serde_json::to_string_pretty(&doc).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::Digests;
    use crate::sbom::Package;
    use std::path::PathBuf;

    fn pkg(name: &str, v: &str, files: &[&str]) -> Package {
        Package {
            name: name.into(),
            version: v.into(),
            architecture: None,
            purl: format!("pkg:npm/{name}@{v}"),
            files: files.iter().map(PathBuf::from).collect(),
        }
    }

    #[test]
    fn same_name_packages_get_distinct_spdx_ids() {
        let sbom = Sbom {
            packages: vec![pkg("lru-cache", "7.0.0", &[]), pkg("lru-cache", "10.0.0", &[])],
            file_digests: BTreeMap::new(),
        };
        let doc: serde_json::Value = serde_json::from_str(&write_spdx(&sbom)).unwrap();
        let ids: Vec<&str> = doc["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["SPDXID"].as_str().unwrap())
            .collect();
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn shared_file_is_one_element_with_a_contains_per_owner() {
        let d = Digests { sha1: [1; 20], sha256: [2; 32] };
        let sbom = Sbom {
            packages: vec![pkg("a", "1", &["usr/bin/x"]), pkg("b", "1", &["usr/bin/x"])],
            file_digests: [(PathBuf::from("usr/bin/x"), d)].into(),
        };
        let doc: serde_json::Value = serde_json::from_str(&write_spdx(&sbom)).unwrap();
        let files = doc["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["fileName"], "./usr/bin/x");
        let contains = doc["relationships"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["relationshipType"] == "CONTAINS")
            .count();
        assert_eq!(contains, 2);
    }
}
