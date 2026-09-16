use crate::Sbom;
use serde::Serialize;
use serde_json::json;

pub fn write_spdx(sbom: &Sbom) -> String {
    let mut packages = Vec::new();
    let mut relationships = Vec::new();
    
    for pkg in &sbom.packages {
        let spdx_id = format!("SPDXRef-Package-{}", pkg.name.replace(|c: char| !c.is_ascii_alphanumeric(), "-"));
        
        packages.push(json!({
            "SPDXID": spdx_id,
            "name": pkg.name,
            "versionInfo": pkg.version,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": pkg.purl
                }
            ]
        }));
        
        relationships.push(json!({
            "spdxElementId": "SPDXRef-RootPackage",
            "relatedSpdxElement": spdx_id,
            "relationshipType": "DEPENDS_ON"
        }));
    }
    
    let doc = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Bedrock-SBOM",
        "documentNamespace": "http://spdx.org/spdxdocs/bedrock-sbom-1.0",
        "packages": packages,
        "relationships": relationships
    });
    
    serde_json::to_string_pretty(&doc).unwrap()
}
