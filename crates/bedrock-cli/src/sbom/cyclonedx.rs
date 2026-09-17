use crate::sbom::{document_id, Sbom};
use serde_json::json;

pub fn write_cyclonedx(sbom: &Sbom) -> String {
    let mut components = Vec::new();

    for pkg in &sbom.packages {
        components.push(json!({
            "type": "library",
            "name": pkg.name,
            "version": pkg.version,
            "purl": pkg.purl
        }));
    }

    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        // Must be unique per document (CycloneDX requires a distinct serial
        // number per BOM); a fixed value reused across every SBOM Bedrock
        // emits would make them indistinguishable.
        "serialNumber": format!("urn:uuid:{}", document_id()),
        "version": 1,
        "components": components
    });

    serde_json::to_string_pretty(&doc).unwrap()
}
