use std::path::{Path, PathBuf};
use crate::{Package, Result};

pub fn parse_node(
    inventory: &bedrock_fs::FileInventory,
) -> Result<Vec<Package>> {
    let mut packages = Vec::new();
    // For node, we look for package.json in node_modules
    for (path, _) in &inventory.files {
        let path_str = path.to_string_lossy();
        if path_str.contains("node_modules") && path_str.ends_with("package.json") {
            // Very naive parser for phase 1
            // In a real implementation we would extract and read the package.json
            let parts: Vec<&str> = path_str.split('/').collect();
            let mut name = "unknown";
            // usually .../node_modules/<name>/package.json
            for i in 0..parts.len() {
                if parts[i] == "node_modules" && i + 2 == parts.len() {
                    name = parts[i+1];
                    break;
                }
            }
            
            if name != "unknown" {
                let purl = format!("pkg:npm/{}@unknown", name);
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
