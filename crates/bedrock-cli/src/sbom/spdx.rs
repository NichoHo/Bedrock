use crate::sbom::{document_id, Sbom};
use serde_json::json;

pub fn write_spdx(sbom: &Sbom) -> String {
    let mut packages = Vec::new();
    let mut relationships = Vec::new();
    let mut describes = Vec::new();

    for pkg in &sbom.packages {
        let spdx_id = format!(
            "SPDXRef-Package-{}",
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
