use crate::sbom::{Package, SbomError};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Reads `/etc/os-release` from the image, if present, to get the distro id
/// (e.g. "debian", "ubuntu") and version for the PURL, instead of hardcoding
/// "debian" for every dpkg-based image.
fn detect_distro<F>(inventory: &crate::fs::FileInventory, resolver: &F) -> (String, Option<String>)
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let default = ("debian".to_string(), None);
    let os_release_path = Path::new("etc/os-release");
    let Some(meta) = inventory.files.get(os_release_path) else {
        return default;
    };
    let Some(tar_path) = resolver(&meta.layer_digest) else {
        return default;
    };
    let Ok(data) = inventory.extract_file(os_release_path, &tar_path) else {
        return default;
    };
    let text = String::from_utf8_lossy(&data);

    let mut id = None;
    let mut version_id = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = Some(v.trim_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            version_id = Some(v.trim_matches('"').to_string());
        }
    }
    (id.unwrap_or_else(|| default.0.clone()), version_id)
}

/// Percent-encodes the handful of characters that show up in Debian version
/// strings and are not legal unescaped in a PURL: currently just the epoch
/// separator `:`. Full RFC 3986 percent-encoding is deferred until a package
/// name/version actually needs it.
fn purl_escape_version(version: &str) -> String {
    version.replace(':', "%3A")
}

pub fn parse_dpkg<F>(inventory: &crate::fs::FileInventory, resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let status_path = Path::new("var/lib/dpkg/status");

    let status_meta = match inventory.files.get(status_path) {
        Some(m) => m,
        None => return Ok(Vec::new()), // No dpkg installed
    };

    let tar_path = resolver(&status_meta.layer_digest)
        .ok_or_else(|| SbomError::Parse("Layer tarball not found".into()))?;

    let status_data = inventory.extract_file(status_path, &tar_path)?;
    let status_text = String::from_utf8_lossy(&status_data);

    let (distro_id, distro_version) = detect_distro(inventory, &resolver);
    let mut packages = parse_status(&status_text, &distro_id, distro_version.as_deref());

    // Group each package's file list by the layer that owns its .list file,
    // so every list living in the same layer is extracted in one archive pass
    // instead of re-opening (and re-gunzipping) the layer once per package.
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
        let Some(tar_path) = resolver(&layer_digest) else { continue };
        let paths: Vec<&Path> = files.iter().map(|(p, _)| p.as_path()).collect();
        let extracted = inventory
            .extract_files(&paths, &tar_path)
            .map_err(|e| SbomError::Parse(format!("failed to extract dpkg file lists: {e}")))?;
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

    Ok(packages)
}

pub fn parse_status(
    status_text: &str,
    distro_id: &str,
    distro_version: Option<&str>,
) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut current_pkg: Option<String> = None;
    let mut current_ver: Option<String> = None;
    let mut current_arch: Option<String> = None;
    let mut current_status: Option<String> = None;

    let mut push_pkg = |name: String, ver: String, arch: String, status: String| {
        // dpkg status lines are "Status: <want> <flag> <state>". Only "installed"
        // in the state field means the package is actually present; "config-files",
        // "half-installed", etc. must not be reported as installed.
        let is_installed = status.split_whitespace().nth(2) == Some("installed");
        if is_installed {
            let mut purl = format!(
                "pkg:deb/{}/{}@{}?arch={}",
                distro_id,
                name,
                purl_escape_version(&ver),
                arch
            );
            if let Some(v) = distro_version {
                purl.push_str(&format!("&distro={}-{}", distro_id, v));
            }
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
        let pkgs = parse_status(status, "debian", None);
        assert_eq!(pkgs.len(), 2);

        assert_eq!(pkgs[0].name, "libacl1");
        assert_eq!(pkgs[0].version, "2.3.1-1");
        assert_eq!(pkgs[0].architecture, Some("amd64".to_string()));

        assert_eq!(pkgs[1].name, "adduser");
        assert_eq!(pkgs[1].version, "3.129");
        assert_eq!(pkgs[1].architecture, Some("all".to_string()));
    }

    #[test]
    fn non_installed_states_are_excluded() {
        let status = "Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.15-2+b2

Package: gone
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0

Package: broken
Status: install ok half-installed
Architecture: amd64
Version: 1.0
";
        let pkgs = parse_status(status, "debian", None);
        assert_eq!(pkgs.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["bash"]);
    }

    #[test]
    fn last_record_without_trailing_blank_line_is_included() {
        let status =
            "Package: lastpkg\nStatus: install ok installed\nArchitecture: all\nVersion: 9.9";
        let pkgs = parse_status(status, "debian", None);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lastpkg");
    }

    #[test]
    fn epoch_colon_is_percent_encoded_in_purl() {
        let status = "Package: libattr1\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:2.5.1-4\n";
        let pkgs = parse_status(status, "ubuntu", Some("22.04"));
        assert_eq!(
            pkgs[0].purl,
            "pkg:deb/ubuntu/libattr1@1%3A2.5.1-4?arch=amd64&distro=ubuntu-22.04"
        );
    }
}
