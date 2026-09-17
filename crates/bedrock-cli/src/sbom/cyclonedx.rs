use crate::sbom::Sbom;
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
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "components": components
    });

    serde_json::to_string_pretty(&doc).unwrap()
}





