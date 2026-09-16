use std::path::PathBuf;
use crate::{Package, Result};

pub fn parse_python(
    inventory: &bedrock_fs::FileInventory,
) -> Result<Vec<Package>> {
    let mut packages = Vec::new();
    // Look for .dist-info/METADATA
    for (path, _) in &inventory.files {
        let path_str = path.to_string_lossy();
        if path_str.ends_with("METADATA") && path_str.contains(".dist-info") {
            let parts: Vec<&str> = path_str.split('/').collect();
            if let Some(dist_info) = parts.iter().find(|p| p.ends_with(".dist-info")) {
                let name = dist_info.split('-').next().unwrap_or("unknown");
                let purl = format!("pkg:pypi/{}@unknown", name);
                packages.push(Package {
                    name: name.to_string(),
                    version: "unknown".to_string(),
                    architecture: None,
                    purl,
                    files: vec![path.clone()],
                });
            }
        }
    }
    Ok(packages)
}
