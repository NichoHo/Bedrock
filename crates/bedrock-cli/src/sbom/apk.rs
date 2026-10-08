use crate::sbom::{read_file, OsRelease, Package};
use anyhow::Result;
use std::path::PathBuf;

pub fn parse_apk<F>(inventory: &crate::fs::FileInventory, resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    // apk is shared by Alpine, Wolfi, Chainguard and others; the PURL
    // namespace has to name the distro or vulnerability matching looks in the
    // wrong advisory feed.
    let os = OsRelease::read(inventory, &resolver);
    let namespace = os.id.as_deref().unwrap_or("alpine");
    // Merged-/usr images (Wolfi, Chainguard) make /lib a symlink to usr/lib,
    // so the database's real tar path is under usr/.
    for path in ["lib/apk/db/installed", "usr/lib/apk/db/installed"] {
        if let Some(db) = read_file(inventory, &resolver, path)? {
            let text = String::from_utf8_lossy(&db);
            return Ok(parse_status(&text, namespace, os.version_id.as_deref()));
        }
    }
    Ok(Vec::new()) // No apk installed
}

pub fn parse_status(db_text: &str, namespace: &str, distro_version: Option<&str>) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut name: Option<String> = None;
    let mut ver: Option<String> = None;
    let mut arch: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut files: Vec<PathBuf> = Vec::new();
    let mut dir = String::new();

    // A stanza ends at a blank line or end of input.
    let mut flush = |name: &mut Option<String>,
                     ver: &mut Option<String>,
                     arch: &mut Option<String>,
                     origin: &mut Option<String>,
                     files: &mut Vec<PathBuf>| {
        if let (Some(n), Some(v)) = (name.take(), ver.take()) {
            let a = arch.clone().unwrap_or_else(|| "x86_64".to_string());
            let qualifier =
                distro_version.map(|dv| format!("&distro={namespace}-{dv}")).unwrap_or_default();
            packages.push(Package {
                purl: format!("pkg:apk/{namespace}/{n}@{v}?arch={a}{qualifier}"),
                name: n,
                version: v,
                architecture: arch.take(),
                source: origin.take(),
                files: std::mem::take(files),
            });
        }
        *arch = None;
        *origin = None;
        files.clear();
    };

    for line in db_text.lines() {
        if line.is_empty() {
            flush(&mut name, &mut ver, &mut arch, &mut origin, &mut files);
            dir.clear();
        } else if let Some(rest) = line.strip_prefix("P:") {
            name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("V:") {
            ver = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("A:") {
            arch = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("o:") {
            origin = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("F:") {
            dir = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("R:") {
            files.push(PathBuf::from(if dir.is_empty() {
                rest.trim().to_string()
            } else {
                format!("{dir}/{}", rest.trim())
            }));
        }
    }
    flush(&mut name, &mut ver, &mut arch, &mut origin, &mut files);

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
        let pkgs = parse_status(status, "alpine", None);
        assert_eq!(pkgs.len(), 2);

        assert_eq!(pkgs[0].name, "musl");
        assert_eq!(pkgs[0].version, "1.2.4-r2");
        assert_eq!(pkgs[0].architecture, Some("x86_64".to_string()));

        assert_eq!(pkgs[1].name, "busybox");
        assert_eq!(pkgs[1].version, "1.36.1-r15");
        assert_eq!(pkgs[1].architecture, Some("x86_64".to_string()));
        assert_eq!(pkgs[0].purl, "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64");
    }

    #[test]
    fn purl_namespace_follows_the_distro() {
        let db = "P:glibc
V:2.39-r5
A:aarch64

";
        assert_eq!(
            parse_status(db, "wolfi", None)[0].purl,
            "pkg:apk/wolfi/glibc@2.39-r5?arch=aarch64"
        );
        assert_eq!(
            parse_status(db, "alpine", Some("3.20.0"))[0].purl,
            "pkg:apk/alpine/glibc@2.39-r5?arch=aarch64&distro=alpine-3.20.0"
        );
    }
}
