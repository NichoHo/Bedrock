use crate::sbom::{Package, SbomError};
use anyhow::Result;
use std::path::{Path, PathBuf};

pub fn parse_apk<F>(inventory: &crate::fs::FileInventory, resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let db_path = Path::new("lib/apk/db/installed");
    let packages = Vec::new();

    let db_meta = match inventory.files.get(db_path) {
        Some(m) => m,
        None => return Ok(packages), // No apk installed
    };

    let tar_path = resolver(&db_meta.layer_digest)
        .ok_or_else(|| SbomError::Parse("Layer tarball not found".into()))?;

    let db_data = inventory.extract_file(db_path, &tar_path)?;
    let db_text = String::from_utf8_lossy(&db_data);

    let packages = parse_status(&db_text);
    Ok(packages)
}

pub fn parse_status(db_text: &str) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut current_pkg: Option<String> = None;
    let mut current_ver: Option<String> = None;
    let mut current_arch: Option<String> = None;
    let mut current_files: Vec<PathBuf> = Vec::new();
    let mut current_dir = String::new();

    for line in db_text.lines() {
        if line.is_empty() {
            if let (Some(name), Some(ver)) = (&current_pkg, &current_ver) {
                let arch_str = current_arch.clone().unwrap_or_else(|| "x86_64".to_string());
                let purl = format!("pkg:apk/alpine/{}@{}?arch={}", name, ver, arch_str);

                packages.push(Package {
                    name: name.to_string(),
                    version: ver.to_string(),
                    architecture: current_arch.clone(),
                    purl,
                    files: current_files.clone(),
                });
            }
            current_pkg = None;
            current_ver = None;
            current_arch = None;
            current_files.clear();
            current_dir.clear();
            continue;
        }

        if let Some(rest) = line.strip_prefix("P:") {
            current_pkg = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("V:") {
            current_ver = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("A:") {
            current_arch = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("F:") {
            current_dir = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("R:") {
            let file_path = if current_dir.is_empty() {
                rest.trim().to_string()
            } else {
                format!("{}/{}", current_dir, rest.trim())
            };
            current_files.push(PathBuf::from(file_path));
        }
    }

    if let (Some(name), Some(ver)) = (&current_pkg, &current_ver) {
        let arch_str = current_arch.clone().unwrap_or_else(|| "x86_64".to_string());
        let purl = format!("pkg:apk/alpine/{}@{}?arch={}", name, ver, arch_str);

        packages.push(Package {
            name: name.to_string(),
            version: ver.to_string(),
            architecture: current_arch.clone(),
            purl,
            files: current_files.clone(),
        });
    }

    packages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_apk() {
        let status = "P:musl
V:1.2.4-r2
A:x86_64
S:382218
I:634880
T:the musl c library (libc)
U:http://www.musl-libc.org/
L:MIT
m:Timo Teras@iki.fi>
t:1699538356
c:b862372d8e34becefc3d59e86b033cfbbff780b1
C:Q1cZzL3gUeM6eN6iN/x3uF+rW6bHk=

P:busybox
V:1.36.1-r15
A:x86_64
S:513470
I:966656
T:Size optimized toolbox of many common UNIX utilities
U:https://busybox.net/
L:GPL-2.0-only
m:Natanael Copa <ncopa@alpinelinux.org>
t:1705646194
c:8a9b6c000f074d2b27b9ef8ef231d6fa5ff5ccbf
C:Q1qgW4+bO24G+iR5k8bU/u/5bB+YI=
";
        let pkgs = parse_status(status);
        assert_eq!(pkgs.len(), 2);

        assert_eq!(pkgs[0].name, "musl");
        assert_eq!(pkgs[0].version, "1.2.4-r2");
        assert_eq!(pkgs[0].architecture, Some("x86_64".to_string()));

        assert_eq!(pkgs[1].name, "busybox");
        assert_eq!(pkgs[1].version, "1.36.1-r15");
        assert_eq!(pkgs[1].architecture, Some("x86_64".to_string()));
    }
}
