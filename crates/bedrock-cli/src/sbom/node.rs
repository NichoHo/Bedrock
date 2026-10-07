use crate::fs::FileInventory;
use crate::sbom::{read_files, Package};
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(serde::Deserialize)]
struct PackageJson {
    name: Option<String>,
    version: Option<String>,
}

/// The directory of the npm package that owns `path`: the innermost
/// `.../node_modules/<pkg>` or `.../node_modules/@scope/<pkg>` prefix, or
/// `None` if the path isn't inside one.
fn owning_package_dir(path: &str) -> Option<&str> {
    let idx = path.rfind("node_modules/")? + "node_modules/".len();
    let rest = &path[idx..];
    let segments = if rest.starts_with('@') { 2 } else { 1 };
    let mut end = idx;
    let mut parts = rest.split('/');
    for _ in 0..segments {
        let part = parts.next().filter(|p| !p.is_empty())?;
        end += part.len() + 1;
    }
    // `end` overshoots by the trailing slash when the path *is* the package dir.
    Some(&path[..(end - 1).min(path.len())])
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

pub fn parse_node<F>(inventory: &FileInventory, resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let mut manifests: Vec<PathBuf> = inventory
        .files
        .keys()
        .filter(|p| p.to_str().and_then(package_dir_for).is_some())
        .cloned()
        .collect();
    manifests.sort();
    let contents = read_files(inventory, &resolver, &manifests)?;

    let mut packages = Vec::new();
    let mut by_dir: HashMap<String, usize> = HashMap::new();
    for path in manifests {
        let path_str = path.to_str().unwrap_or_default();
        let dir = path_str.strip_suffix("/package.json").unwrap_or(path_str).to_string();
        let mut name = package_dir_for(path_str).unwrap_or("unknown").to_string();
        let mut version = "unknown".to_string();
        if let Some(parsed) =
            contents.get(&path).and_then(|d| serde_json::from_slice::<PackageJson>(d).ok())
        {
            name = parsed.name.unwrap_or(name);
            version = parsed.version.unwrap_or(version);
        }
        by_dir.insert(dir, packages.len());
        let purl = format!("pkg:npm/{}@{}", name.replace('@', "%40"), version);
        packages.push(Package { name, version, architecture: None, purl, files: Vec::new() });
    }

    // Assign every file to the innermost package directory containing it, so
    // files under a nested node_modules belong to the nested package.
    for path in inventory.files.keys() {
        let Some(dir) = path.to_str().and_then(owning_package_dir) else { continue };
        if let Some(&i) = by_dir.get(dir) {
            packages[i].files.push(path.clone());
        }
    }
    for pkg in &mut packages {
        pkg.files.sort();
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

    #[test]
    fn files_belong_to_innermost_package() {
        assert_eq!(owning_package_dir("app/node_modules/a/lib/x.js"), Some("app/node_modules/a"));
        assert_eq!(
            owning_package_dir("app/node_modules/a/node_modules/@s/b/index.js"),
            Some("app/node_modules/a/node_modules/@s/b")
        );
        assert_eq!(owning_package_dir("app/node_modules/a"), Some("app/node_modules/a"));
        assert_eq!(owning_package_dir("app/node_modules/@s"), None);
        assert_eq!(owning_package_dir("app/src/index.js"), None);
    }
}
