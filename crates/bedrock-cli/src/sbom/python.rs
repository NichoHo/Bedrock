use crate::sbom::Package;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Reads the `Name:` and `Version:` fields out of a `.dist-info/METADATA` file
/// (RFC 822-ish key: value headers). Falls back to `None` per field if the
/// file is missing the header or isn't valid UTF-8.
fn parse_metadata(data: &[u8]) -> (Option<String>, Option<String>) {
    let text = String::from_utf8_lossy(data);
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Name:") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            version = Some(v.trim().to_string());
        }
        if name.is_some() && version.is_some() {
            break;
        }
    }
    (name, version)
}

/// The `<name>-<version>` component of a `.../<name>-<version>.dist-info/METADATA`
/// path, used only as a fallback when METADATA can't be read or parsed.
fn dist_info_name(path_str: &str) -> Option<&str> {
    let parts: Vec<&str> = path_str.split('/').collect();
    parts
        .iter()
        .rev()
        .find(|p| p.ends_with(".dist-info"))
        .map(|s| s.strip_suffix(".dist-info").unwrap_or(s).split('-').next().unwrap_or("unknown"))
}

pub fn parse_python<F>(inventory: &crate::fs::FileInventory, resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let mut by_layer: std::collections::HashMap<String, Vec<PathBuf>> =
        std::collections::HashMap::new();
    for (path, meta) in &inventory.files {
        let path_str = path.to_string_lossy().replace('\\', "/");
        if path_str.ends_with("METADATA") && path_str.contains(".dist-info") {
            by_layer.entry(meta.layer_digest.clone()).or_default().push(path.clone());
        }
    }

    let mut packages = Vec::new();
    for (layer_digest, paths) in by_layer {
        let extracted = resolver(&layer_digest)
            .and_then(|tar_path| {
                let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
                inventory.extract_files(&refs, &tar_path).ok()
            })
            .unwrap_or_default();

        for path in paths {
            let path_str = path.to_string_lossy().replace('\\', "/");
            let fallback_name = dist_info_name(&path_str).unwrap_or("unknown").to_string();

            let (name, version) = match extracted.get(&path) {
                Some(data) => {
                    let (n, v) = parse_metadata(data);
                    (n.unwrap_or(fallback_name), v.unwrap_or_else(|| "unknown".to_string()))
                }
                None => (fallback_name, "unknown".to_string()),
            };

            let purl = format!("pkg:pypi/{}@{}", name, version);
            packages.push(Package { name, version, architecture: None, purl, files: vec![path] });
        }
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_and_version_from_metadata() {
        let data =
            b"Metadata-Version: 2.1\nName: requests\nVersion: 2.25.1\nSummary: HTTP library\n";
        let (name, version) = parse_metadata(data);
        assert_eq!(name.as_deref(), Some("requests"));
        assert_eq!(version.as_deref(), Some("2.25.1"));
    }

    #[test]
    fn fallback_name_from_dist_info_dir() {
        let p = "usr/lib/python3.9/site-packages/requests-2.25.1.dist-info/METADATA";
        assert_eq!(dist_info_name(p), Some("requests"));
    }
}
