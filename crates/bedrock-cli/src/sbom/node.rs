use crate::sbom::Package;
use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(serde::Deserialize)]
struct PackageJson {
    name: Option<String>,
    version: Option<String>,
}

/// The `<pkg>` (or `@scope/<pkg>`) component of a
/// `.../node_modules/<pkg>/package.json` path.
fn package_dir_for(path_str: &str) -> Option<&str> {
    let (before, _) = path_str.rsplit_once("/package.json")?;
    let (_, pkg_dir) = before.rsplit_once("node_modules/")?;
    // A scoped package's package.json lives at node_modules/@scope/name/package.json;
    // pkg_dir is already "@scope/name" here since rsplit_once found the *last*
    // "node_modules/" and everything after it, slash and all.
    Some(pkg_dir)
}

pub fn parse_node<F>(inventory: &crate::fs::FileInventory, resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let mut by_layer: std::collections::HashMap<String, Vec<PathBuf>> =
        std::collections::HashMap::new();
    for (path, meta) in &inventory.files {
        let path_str = path.to_string_lossy().replace('\\', "/");
        if package_dir_for(&path_str).is_some() {
            by_layer.entry(meta.layer_digest.clone()).or_default().push(path.clone());
        }
    }

    let mut packages = Vec::new();
    for (layer_digest, paths) in by_layer {
        let path_str_fallback_name = |p: &Path| -> String {
            package_dir_for(&p.to_string_lossy().replace('\\', "/"))
                .unwrap_or("unknown")
                .to_string()
        };

        let Some(tar_path) = resolver(&layer_digest) else {
            for path in &paths {
                let name = path_str_fallback_name(path);
                packages.push(Package {
                    name: name.clone(),
                    version: "unknown".to_string(),
                    architecture: None,
                    purl: format!("pkg:npm/{}@unknown", name),
                    files: vec![path.clone()],
                });
            }
            continue;
        };

        let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
        let extracted = inventory.extract_files(&refs, &tar_path).unwrap_or_default();

        for path in paths {
            let mut name = path_str_fallback_name(&path);
            let mut version = "unknown".to_string();
            if let Some(data) = extracted.get(&path) {
                if let Ok(parsed) = serde_json::from_slice::<PackageJson>(data) {
                    if let Some(n) = parsed.name {
                        name = n;
                    }
                    if let Some(v) = parsed.version {
                        version = v;
                    }
                }
            }
            let purl = format!("pkg:npm/{}@{}", name, version);
            packages.push(Package { name, version, architecture: None, purl, files: vec![path] });
        }
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_package_dir() {
        assert_eq!(package_dir_for("app/node_modules/express/package.json"), Some("express"));
    }

    #[test]
    fn scoped_package_dir() {
        assert_eq!(
            package_dir_for("app/node_modules/@babel/core/package.json"),
            Some("@babel/core")
        );
    }
}
