use crate::sbom::{Package, SbomError};
use anyhow::Result;
use std::path::{Path, PathBuf};

pub fn parse_dpkg<F>(inventory: &crate::fs::FileInventory, resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let status_path = Path::new("var/lib/dpkg/status");

    // Find status file in inventory
    let status_meta = match inventory.files.get(status_path) {
        Some(m) => m,
        None => return Ok(Vec::new()), // No dpkg installed
    };

    let tar_path = resolver(&status_meta.layer_digest)
        .ok_or_else(|| SbomError::Parse("Layer tarball not found".into()))?;

    let status_data = inventory.extract_file(status_path, &tar_path)?;
    let status_text = String::from_utf8_lossy(&status_data);

    let mut packages = parse_status(&status_text);

    // Group lists by layer to avoid quadratic extraction
    let mut lists_by_layer: std::collections::HashMap<String, Vec<(PathBuf, usize)>> =
        std::collections::HashMap::new();

    for (i, pkg) in packages.iter().enumerate() {
        let name = &pkg.name;
        let arch = pkg.architecture.as_deref().unwrap_or("amd64");

        let list_path = PathBuf::from(format!("var/lib/dpkg/info/{}.list", name));
        let list_path_arch = PathBuf::from(format!("var/lib/dpkg/info/{}:{}.list", name, arch));

        if let Some(meta) = inventory.files.get(&list_path) {
            lists_by_layer.entry(meta.layer_digest.clone()).or_default().push((list_path, i));
        } else if let Some(meta) = inventory.files.get(&list_path_arch) {
            lists_by_layer.entry(meta.layer_digest.clone()).or_default().push((list_path_arch, i));
        }
    }

    for (layer_digest, files) in lists_by_layer {
        if let Some(tar_path) = resolver(&layer_digest) {
            let paths: Vec<&Path> = files.iter().map(|(p, _)| p.as_path()).collect();
            if let Ok(extracted) = inventory.extract_files(&paths, &tar_path) {
                for (path, pkg_idx) in files {
                    if let Some(list_data) = extracted.get(&path) {
                        let list_text = String::from_utf8_lossy(list_data);
                        for f in list_text.lines() {
                            if !f.trim().is_empty() {
                                let clean_path = f.trim().strip_prefix('/').unwrap_or(f.trim());
                                packages[pkg_idx].files.push(PathBuf::from(clean_path));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(packages)
}

pub fn parse_status(status_text: &str) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut current_pkg: Option<String> = None;
    let mut current_ver: Option<String> = None;
    let mut current_arch: Option<String> = None;
    let mut current_status: Option<String> = None;

    let mut push_pkg = |name: String, ver: String, arch: String, status: String| {
        if status.contains("installed") && !status.contains("not-installed") {
            let purl = format!("pkg:deb/debian/{}@{}?arch={}", name, ver, arch);
            packages.push(Package {
                name,
                version: ver,
                architecture: Some(arch),
                purl,
                files: Vec::new(),
            });
        }
    };

    for line in status_text.lines() {
        if line.is_empty() {
            if let (Some(name), Some(ver), Some(arch), Some(status)) =
                (&current_pkg, &current_ver, &current_arch, &current_status)
            {
                push_pkg(name.clone(), ver.clone(), arch.clone(), status.clone());
            }
            current_pkg = None;
            current_ver = None;
            current_arch = None;
            current_status = None;
            continue;
        }

        if let Some(rest) = line.strip_prefix("Package: ") {
            current_pkg = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Version: ") {
            current_ver = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Architecture: ") {
            current_arch = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Status: ") {
            current_status = Some(rest.trim().to_string());
        }
    }

    // Handle last package if file doesn't end with a blank line
    if let (Some(name), Some(ver), Some(arch), Some(status)) =
        (&current_pkg, &current_ver, &current_arch, &current_status)
    {
        push_pkg(name.clone(), ver.clone(), arch.clone(), status.clone());
    }

    packages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_status() {
        let status = "Package: libacl1
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 45
Maintainer: Guillem Jover <guillem@debian.org>
Architecture: amd64
Multi-Arch: same
Source: acl
Version: 2.3.1-1
Depends: libc6 (>= 2.33), libattr1 (>= 1:2.4.46-8)
Description: Access control list shared library

Package: adduser
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 673
Maintainer: Debian Adduser Developers <adduser@packages.debian.org>
Architecture: all
Version: 3.129
Depends: passwd (>= 1:4.0.12), debconf (>= 0.5) | debconf-2.0
Description: add and remove users and groups
";
        let pkgs = parse_status(status);
        assert_eq!(pkgs.len(), 2);

        assert_eq!(pkgs[0].name, "libacl1");
        assert_eq!(pkgs[0].version, "2.3.1-1");
        assert_eq!(pkgs[0].architecture, Some("amd64".to_string()));

        assert_eq!(pkgs[1].name, "adduser");
        assert_eq!(pkgs[1].version, "3.129");
        assert_eq!(pkgs[1].architecture, Some("all".to_string()));
    }
}
