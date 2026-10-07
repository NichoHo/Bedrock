use crate::sbom::{document_id, Sbom};
use serde_json::json;

pub fn write_cyclonedx(sbom: &Sbom) -> String {
    let mut components = Vec::new();

    for (i, pkg) in sbom.packages.iter().enumerate() {
        // A package's files are nested components of type "file", which is
        // how CycloneDX expresses ownership. File components get no bom-ref:
        // a path owned by two packages would otherwise repeat one, and
        // bom-refs must be unique.
        let files: Vec<_> = pkg
            .files
            .iter()
            .filter_map(|path| {
                let d = sbom.file_digests.get(path)?;
                Some(json!({
                    "type": "file",
                    "name": format!("/{}", path.display()),
                    "hashes": [
                        { "alg": "SHA-1", "content": hex::encode(d.sha1) },
                        { "alg": "SHA-256", "content": hex::encode(d.sha256) }
                    ]
                }))
            })
            .collect();

        let mut component = json!({
            "type": "library",
            // The index keeps refs unique across same-name, same-version packages.
            "bom-ref": format!("pkg-{i}"),
            "name": pkg.name,
            "version": pkg.version,
            "purl": pkg.purl
        });
        if !files.is_empty() {
            component["components"] = json!(files);
        }
        components.push(component);
    }

    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        // Must be unique per document (CycloneDX requires a distinct serial
        // number per BOM); a fixed value reused across every SBOM Bedrock
        // emits would make them indistinguishable.
        "serialNumber": format!("urn:uuid:{}", document_id()),
        "version": 1,
        "metadata": {
            "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "bedrock",
                    "version": env!("CARGO_PKG_VERSION")
                }]
            }
        },
        "components": components
    });

    serde_json::to_string_pretty(&doc).unwrap()
}
