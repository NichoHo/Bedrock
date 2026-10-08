use crate::fs::FileInventory;
use crate::sbom::{read_file, read_files, OsRelease, Package};
use anyhow::Result;
use std::path::PathBuf;

/// Percent-encodes the handful of characters that show up in Debian version
/// strings and are not legal unescaped in a PURL: currently just the epoch
/// separator `:`. Full RFC 3986 percent-encoding is deferred until a package
/// name/version actually needs it.
fn purl_escape_version(version: &str) -> String {
    version.replace(':', "%3A")
}

/// Distroless images have no `var/lib/dpkg/status`. Instead each package gets
/// its own stanza file in `var/lib/dpkg/status.d/<name>` (with no `Status:`
/// field, since everything there is installed) and its file list in
/// `status.d/<name>.md5sums`.
const STATUS_D: &str = "var/lib/dpkg/status.d/";

pub fn parse_dpkg<F>(inventory: &FileInventory, resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let os = OsRelease::read(inventory, &resolver);
    let distro_id = os.id.as_deref().unwrap_or("debian");
    let distro_version = os.version_id.as_deref();

    let mut packages = Vec::new();
    if let Some(status) = read_file(inventory, &resolver, "var/lib/dpkg/status")? {
        packages = parse_status(&String::from_utf8_lossy(&status), distro_id, distro_version);
        attach_file_lists(inventory, &resolver, &mut packages, |pkg| {
            let arch = pkg.architecture.as_deref().unwrap_or("amd64");
            vec![
                format!("var/lib/dpkg/info/{}.list", pkg.name),
                format!("var/lib/dpkg/info/{}:{arch}.list", pkg.name),
            ]
        })?;
    }

    let mut stanza_paths: Vec<PathBuf> = inventory
        .files
        .keys()
        .filter(|p| {
            p.to_str().and_then(|s| s.strip_prefix(STATUS_D)).is_some_and(|name| {
                !name.is_empty() && !name.contains('/') && !name.ends_with(".md5sums")
            })
        })
        .cloned()
        .collect();
    stanza_paths.sort();
    if !stanza_paths.is_empty() {
        let stanzas = read_files(inventory, &resolver, &stanza_paths)?;
        let mut distroless = Vec::new();
        for path in &stanza_paths {
            if let Some(data) = stanzas.get(path) {
                distroless.extend(parse_stanzas(
                    &String::from_utf8_lossy(data),
                    distro_id,
                    distro_version,
                    false,
                ));
            }
        }
        attach_file_lists(inventory, &resolver, &mut distroless, |pkg| {
            vec![format!("{STATUS_D}{}.md5sums", pkg.name)]
        })?;
        packages.extend(distroless);
    }

    Ok(packages)
}

/// Fills each package's `files` from the first of `candidates(pkg)` that
/// exists. Handles both `.list` files (one absolute path per line) and
/// `.md5sums` files (`<md5>  <relative path>` per line).
fn attach_file_lists<F>(
    inventory: &FileInventory,
    resolver: &F,
    packages: &mut [Package],
    candidates: impl Fn(&Package) -> Vec<String>,
) -> Result<()>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let chosen: Vec<Option<PathBuf>> = packages
        .iter()
        .map(|pkg| {
            candidates(pkg).into_iter().map(PathBuf::from).find(|p| inventory.files.contains_key(p))
        })
        .collect();
    let wanted: Vec<PathBuf> = chosen.iter().flatten().cloned().collect();
    let lists = read_files(inventory, resolver, &wanted)?;

    for (pkg, list_path) in packages.iter_mut().zip(chosen) {
        let Some(data) = list_path.and_then(|p| lists.get(&p)) else { continue };
        for line in String::from_utf8_lossy(data).lines() {
            let line = line.trim();
            // md5sums lines are "<32 hex chars>  <path>"; .list lines are just a path.
            let path = match line.split_once("  ") {
                Some((hash, path)) if hash.len() == 32 => path,
                _ => line,
            };
            let path = path.trim_start_matches('/');
            // .list files include "/." for the root directory.
            if !path.is_empty() && path != "." {
                pkg.files.push(PathBuf::from(path));
            }
        }
    }
    Ok(())
}

pub fn parse_status(
    status_text: &str,
    distro_id: &str,
    distro_version: Option<&str>,
) -> Vec<Package> {
    parse_stanzas(status_text, distro_id, distro_version, true)
}

/// Parses dpkg control stanzas. With `status_required`, only stanzas whose
/// `Status:` state is "installed" count (the main status file also keeps
/// removed packages' config-files records). Distroless `status.d` stanzas
/// carry no `Status:` field at all and are all installed.
fn parse_stanzas(
    text: &str,
    distro_id: &str,
    distro_version: Option<&str>,
    status_required: bool,
) -> Vec<Package> {
    let mut packages = Vec::new();
    // Chaining an empty line onto the input flushes the last stanza even when
    // the file doesn't end with a blank line.
    let [mut name, mut version, mut arch, mut status, mut source]: [Option<String>; 5] =
        Default::default();
    for line in text.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            // dpkg status lines are "Status: <want> <flag> <state>". Only
            // "installed" in the state field means the package is present;
            // "config-files", "half-installed", etc. must not be reported.
            let installed = match status.take() {
                Some(s) => s.split_whitespace().nth(2) == Some("installed"),
                None => !status_required,
            };
            if let (Some(n), Some(v), Some(a), true) =
                (name.take(), version.take(), arch.take(), installed)
            {
                let purl = format!(
                    "pkg:deb/{distro_id}/{n}@{}?arch={a}{}",
                    purl_escape_version(&v),
                    distro_version
                        .map(|dv| format!("&distro={distro_id}-{dv}"))
                        .unwrap_or_default()
                );
                packages.push(Package {
                    name: n,
                    version: v,
                    architecture: Some(a),
                    source: source.take(),
                    purl,
                    files: Vec::new(),
                });
            }
            (name, version, arch, source) = (None, None, None, None);
            continue;
        }
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim().to_string();
        match key {
            "Package" => name = Some(value),
            "Version" => version = Some(value),
            "Architecture" => arch = Some(value),
            "Status" => status = Some(value),
            // "Source: glibc (2.36-9)": the name is the first word.
            "Source" => source = value.split_whitespace().next().map(String::from),
            _ => {}
        }
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

    #[test]
    fn distroless_stanza_without_status_counts_as_installed() {
        let stanza = "Package: libc6\nVersion: 2.36-9\nArchitecture: amd64\n";
        assert_eq!(parse_stanzas(stanza, "debian", None, false).len(), 1);
        assert!(parse_stanzas(stanza, "debian", None, true).is_empty());
    }
}
