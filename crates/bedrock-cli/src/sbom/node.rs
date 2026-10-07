use crate::sbom::Package;
use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(serde::Deserialize)]
struct PackageJson {
    name: Option<String>,
    version: Option<String>,
}

/// The `<pkg>` (or `@scope/<pkg>`) component of a
/// `.../node_modules/<pkg>/package.json` path. Returns `None` for a
/// `package.json` deeper inside a package (e.g. `node_modules/minipass/dist/esm/package.json`,
/// a module-type stub), which is not a package of its own.
fn package_dir_for(path_str: &str) -> Option<&str> {
    let before = path_str.strip_suffix("/package.json")?;
    let (_, pkg_dir) = before.rsplit_once("node_modules/")?;
    let segments = pkg_dir.split('/').count();
    let valid = if pkg_dir.starts_with('@') { segments == 2 } else { segments == 1 };
    valid.then_some(pkg_dir)
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

    #[test]
    fn nested_package_json_inside_a_package_is_not_a_package() {
        assert_eq!(package_dir_for("app/node_modules/minipass/dist/esm/package.json"), None);
        assert_eq!(package_dir_for("app/node_modules/@babel/core/lib/package.json"), None);
        assert_eq!(package_dir_for("app/node_modules/a/node_modules/b/package.json"), Some("b"));
    }
}
