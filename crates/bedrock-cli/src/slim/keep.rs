//! The keep set (BEDROCK_SPEC.md 5.6):
//!
//! ```text
//! keep = reached ∪ static closure ∪ files_of(packages owning reached)   [package granularity]
//!      ∪ keep_list ∪ mandatory
//! ```
//!
//! Directories are always kept: they cost nothing, and dropping one breaks
//! mount points, `/tmp` and permissions for no size benefit.
use super::glob;
use crate::fs::{EntryKind, FileInventory};
use crate::sbom::Package;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Version of the built-in mandatory list below. Bump when it changes.
pub const MANDATORY_VERSION: u32 = 1;

/// Paths every image needs to boot that traces routinely miss: the loader and
/// libc, name-service and TLS files, glibc's `dlopen`ed NSS modules, and the
/// package databases (which the pruned image's own SBOM is read from).
pub const MANDATORY: &[&str] = &[
    "etc/passwd",
    "etc/group",
    "etc/nsswitch.conf",
    "etc/hosts",
    "etc/resolv.conf",
    "etc/host.conf",
    "etc/os-release",
    "usr/lib/os-release",
    "etc/localtime",
    "etc/timezone",
    "etc/ld.so.cache",
    "etc/ld.so.conf",
    "etc/ld.so.conf.d/**",
    "etc/ssl/**",
    "etc/pki/**",
    "etc/ca-certificates.conf",
    "usr/share/ca-certificates/**",
    "lib*/ld-linux*",
    "lib/**/ld-linux*",
    "usr/lib*/ld-linux*",
    "usr/lib/**/ld-linux*",
    "lib/ld-musl-*",
    "usr/lib/ld-musl-*",
    "lib*/libc.so*",
    "lib/**/libc.so*",
    "usr/lib*/libc.so*",
    "usr/lib/**/libc.so*",
    "lib/libc.musl-*",
    "lib*/libnss_*",
    "lib/**/libnss_*",
    "usr/lib*/libnss_*",
    "usr/lib/**/libnss_*",
    "var/lib/dpkg/**",
    "lib/apk/db/**",
    "usr/lib/apk/db/**",
    "var/lib/rpm/**",
    "usr/lib/sysimage/rpm/**",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeepList {
    /// Globs relative to the image root (a leading `/` is accepted and dropped).
    pub paths: Vec<String>,
    pub packages: Vec<String>,
}

#[derive(Deserialize)]
struct KeepFile {
    keep: Option<KeepSection>,
}
#[derive(Deserialize, Default)]
struct KeepSection {
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    packages: Vec<String>,
}

impl KeepList {
    pub fn parse(text: &str) -> Result<Self> {
        let f: KeepFile = toml::from_str(text).context("keep-list is not valid TOML")?;
        let k = f.keep.unwrap_or_default();
        Ok(Self {
            paths: k.paths.into_iter().map(|p| p.trim_start_matches('/').to_string()).collect(),
            packages: k.packages,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    Package,
    File,
}

pub struct PlanInput<'a> {
    pub inventory: &'a FileInventory,
    pub packages: &'a [Package],
    /// Image paths reached by the trace, dynamically or by static closure (no leading `/`).
    pub reached: &'a BTreeSet<PathBuf>,
    /// The subset seen by a syscall.
    pub dynamic: &'a BTreeSet<PathBuf>,
    pub keep_list: &'a KeepList,
    pub mandatory: bool,
    pub granularity: Granularity,
}

#[derive(Debug, Default)]
pub struct Plan {
    pub keep: BTreeSet<PathBuf>,
    /// (package name, reason)
    pub removed_packages: Vec<(String, &'static str)>,
    /// Files removed on their own (not as part of a removed package).
    pub removed_files: Vec<(PathBuf, &'static str)>,
    /// Kept without ever being seen touched: (name, `keep_list`|`mandatory`|`closure`).
    pub retained_unreached: Vec<(String, &'static str)>,
}

fn is_doc(p: &Path) -> bool {
    ["usr/share/doc", "usr/share/man", "usr/share/info", "usr/share/lintian"]
        .iter()
        .any(|d| p.starts_with(d))
}

fn s(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

pub fn plan(input: &PlanInput<'_>) -> Plan {
    let inv = &input.inventory.files;
    let mut mandatory_hits: BTreeSet<&Path> = BTreeSet::new();
    let mut keep_list_hits: BTreeSet<&Path> = BTreeSet::new();
    for path in inv.keys() {
        let name = s(path);
        if input.mandatory && MANDATORY.iter().any(|g| glob::matches(g, &name)) {
            mandatory_hits.insert(path);
        }
        if input.keep_list.paths.iter().any(|g| glob::matches(g, &name)) {
            keep_list_hits.insert(path);
        }
    }

    // Per package: why it stays, or why it goes.
    let mut retained: Vec<bool> = Vec::with_capacity(input.packages.len());
    let mut plan = Plan::default();
    for pkg in input.packages {
        // Package file lists include directories; a traced stat of /usr/bin must not
        // count as reaching every package that owns something under it.
        let files: Vec<&PathBuf> = pkg
            .files
            .iter()
            .filter(|f| inv.get(*f).is_some_and(|m| m.kind != EntryKind::Directory))
            .collect();
        let reached: Vec<&&PathBuf> =
            files.iter().filter(|f| input.reached.contains(**f)).collect();
        let dynamic = files.iter().any(|f| input.dynamic.contains(*f));
        // Ok(reason to keep) or Err(reason to remove)
        let verdict: Result<&'static str, &'static str> = if files.is_empty() {
            // Nothing to prune; leave metapackages in the database.
            Ok("reached")
        } else if input.keep_list.packages.contains(&pkg.name)
            || files.iter().any(|f| keep_list_hits.contains(f.as_path()))
        {
            Ok("keep_list")
        } else if files.iter().any(|f| mandatory_hits.contains(f.as_path())) {
            Ok("mandatory")
        } else if reached.iter().any(|f| !is_doc(f)) {
            Ok(if dynamic { "reached" } else { "closure" })
        } else if !reached.is_empty() {
            Err("only_docs_reached")
        } else {
            Err("no_file_reached")
        };
        match verdict {
            Ok(why) => {
                if !files.is_empty() && !dynamic && why != "reached" {
                    plan.retained_unreached.push((pkg.name.clone(), why));
                }
                retained.push(true);
            }
            Err(reason) => {
                plan.removed_packages.push((pkg.name.clone(), reason));
                retained.push(false);
            }
        }
    }
    let retained_names: BTreeSet<&str> = input
        .packages
        .iter()
        .zip(&retained)
        .filter(|(_, r)| **r)
        .map(|(p, _)| p.name.as_str())
        .collect();
    // A name counts as removed only if no retained package shares it (multi-arch).
    let removed_names: BTreeSet<&str> = plan
        .removed_packages
        .iter()
        .map(|(n, _)| n.as_str())
        .filter(|n| !retained_names.contains(n))
        .collect();

    // Paths owned only by removed packages go with them.
    let mut owners: HashMap<&Path, Vec<usize>> = HashMap::new();
    for (i, pkg) in input.packages.iter().enumerate() {
        for f in &pkg.files {
            owners.entry(f.as_path()).or_default().push(i);
        }
    }
    let owned_only_by_removed =
        |p: &Path| owners.get(p).is_some_and(|o| o.iter().all(|&i| !retained[i]));

    let mut keep: BTreeSet<PathBuf> = BTreeSet::new();
    for (path, meta) in inv {
        if meta.kind == EntryKind::Directory {
            keep.insert(path.clone());
        }
    }
    for path in input.reached {
        if inv.contains_key(path) && !owned_only_by_removed(path) {
            keep.insert(path.clone());
        }
    }
    keep.extend(keep_list_hits.iter().map(|p| p.to_path_buf()));
    keep.extend(mandatory_hits.iter().map(|p| p.to_path_buf()));
    if input.granularity == Granularity::Package {
        for (pkg, r) in input.packages.iter().zip(&retained) {
            if *r {
                keep.extend(pkg.files.iter().filter(|f| inv.contains_key(*f)).cloned());
            }
        }
    }
    close_over_links(&mut keep, inv);
    // Package-database files of removed packages go, even though the database
    // directory is mandatory.
    keep.retain(|p| !is_removed_package_metadata(p, &removed_names));

    // Kept, unowned, never seen touched: config pulled in by the closure or the lists.
    let mut unowned: BTreeMap<PathBuf, &'static str> = BTreeMap::new();
    for p in &keep {
        let is_file = inv.get(p).map(|m| &m.kind) == Some(&EntryKind::File);
        if owners.contains_key(p.as_path()) || input.dynamic.contains(p) || !is_file {
            continue;
        }
        let why = if keep_list_hits.contains(p.as_path()) {
            "keep_list"
        } else if mandatory_hits.contains(p.as_path()) {
            "mandatory"
        } else {
            "closure"
        };
        unowned.insert(p.clone(), why);
    }
    plan.retained_unreached.extend(unowned.into_iter().map(|(p, w)| (format!("/{}", s(&p)), w)));

    for (path, meta) in inv {
        if meta.kind == EntryKind::Directory || keep.contains(path) || owned_only_by_removed(path) {
            continue;
        }
        let reason =
            if input.reached.contains(path) { "only_docs_reached" } else { "not_in_closure" };
        plan.removed_files.push((path.clone(), reason));
    }
    plan.removed_files.sort();
    plan.removed_packages.sort();
    plan.retained_unreached.sort();
    plan.keep = keep;
    plan
}

/// `var/lib/dpkg/info/<pkg>[:arch].*` and `var/lib/dpkg/status.d/<pkg>[.md5sums]`.
fn is_removed_package_metadata(p: &Path, removed: &BTreeSet<&str>) -> bool {
    let name = s(p);
    let leaf = |dir: &str| name.strip_prefix(dir).filter(|l| !l.contains('/'));
    if let Some(l) = leaf("var/lib/dpkg/info/") {
        let base = l.split('.').next().unwrap_or(l);
        return removed.contains(base.split(':').next().unwrap_or(base));
    }
    if let Some(l) = leaf("var/lib/dpkg/status.d/") {
        return removed.contains(l.split('.').next().unwrap_or(l));
    }
    false
}

/// A kept symlink needs its target, and a kept hard link its original,
/// or the pruned image holds a dangling reference.
fn close_over_links(keep: &mut BTreeSet<PathBuf>, inv: &HashMap<PathBuf, crate::fs::FileMetadata>) {
    let mut queue: Vec<PathBuf> = keep.iter().cloned().collect();
    while let Some(p) = queue.pop() {
        let target = match inv.get(&p).map(|m| &m.kind) {
            Some(EntryKind::HardLink(t)) => crate::fs::strip_leading_curdir(t),
            Some(EntryKind::Symlink(t)) => lexical_join(p.parent().unwrap_or(Path::new("")), t),
            _ => continue,
        };
        // Keep every component on the way to the target too (directory symlinks).
        let mut cur = PathBuf::new();
        for c in target.components() {
            cur.push(c);
            if inv.contains_key(&cur) && keep.insert(cur.clone()) {
                queue.push(cur.clone());
            }
        }
    }
}

fn lexical_join(base: &Path, rel: &Path) -> PathBuf {
    let mut out: Vec<std::ffi::OsString> = if rel.is_absolute() {
        vec![]
    } else {
        base.components().map(|c| c.as_os_str().to_owned()).collect()
    };
    for c in rel.components() {
        match c {
            std::path::Component::Normal(n) => out.push(n.to_owned()),
            std::path::Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out.iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{FileInventory, FileMetadata};

    fn meta(kind: EntryKind) -> FileMetadata {
        FileMetadata { layer_digest: "l".into(), size: 1, mode: 0o644, kind, digests: None }
    }

    fn pkg(name: &str, files: &[&str]) -> Package {
        Package {
            name: name.into(),
            version: "1".into(),
            architecture: None,
            source: None,
            purl: format!("pkg:deb/debian/{name}@1"),
            files: files.iter().map(PathBuf::from).collect(),
        }
    }

    fn inventory(entries: &[(&str, EntryKind)]) -> FileInventory {
        let mut inv = FileInventory::new();
        for (p, k) in entries {
            inv.files.insert(PathBuf::from(p), meta(k.clone()));
        }
        inv
    }

    fn set(paths: &[&str]) -> BTreeSet<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn package_granularity_keeps_whole_reached_packages_and_drops_the_rest() {
        let f = EntryKind::File;
        let inv = inventory(&[
            ("usr", EntryKind::Directory),
            ("usr/bin/app", f.clone()),
            ("usr/bin/app-helper", f.clone()),
            ("usr/bin/unused", f.clone()),
            ("usr/share/doc/docsonly/README", f.clone()),
            ("etc/passwd", f.clone()),
            ("srv/data.bin", f.clone()),
            ("srv/unused.bin", f.clone()),
            ("var/lib/dpkg/info/unused.list", f.clone()),
            ("var/lib/dpkg/info/app.list", f.clone()),
        ]);
        let packages = [
            pkg("app", &["usr/bin/app", "usr/bin/app-helper"]),
            pkg("unused", &["usr/bin/unused"]),
            pkg("docsonly", &["usr/share/doc/docsonly/README"]),
            pkg("base-passwd", &["etc/passwd"]),
        ];
        let reached = set(&["usr/bin/app", "srv/data.bin", "usr/share/doc/docsonly/README"]);
        let kl = KeepList::default();
        let p = plan(&PlanInput {
            inventory: &inv,
            packages: &packages,
            reached: &reached,
            dynamic: &reached,
            keep_list: &kl,
            mandatory: true,
            granularity: Granularity::Package,
        });
        assert!(p.keep.contains(Path::new("usr/bin/app-helper")), "whole package is kept");
        assert!(p.keep.contains(Path::new("srv/data.bin")), "reached unowned file");
        assert!(p.keep.contains(Path::new("usr")), "directories always stay");
        assert!(p.keep.contains(Path::new("etc/passwd")), "mandatory");
        assert!(!p.keep.contains(Path::new("srv/unused.bin")));
        assert!(!p.keep.contains(Path::new("usr/bin/unused")));
        assert!(
            !p.keep.contains(Path::new("var/lib/dpkg/info/unused.list")),
            "removed package metadata goes"
        );
        assert!(p.keep.contains(Path::new("var/lib/dpkg/info/app.list")));
        assert_eq!(
            p.removed_packages,
            [
                ("docsonly".to_string(), "only_docs_reached"),
                ("unused".to_string(), "no_file_reached")
            ]
        );
        assert!(p.retained_unreached.contains(&("base-passwd".to_string(), "mandatory")));
        assert!(p.removed_files.contains(&(PathBuf::from("srv/unused.bin"), "not_in_closure")));
    }

    #[test]
    fn file_granularity_drops_unreached_files_of_a_reached_package() {
        let f = EntryKind::File;
        let inv = inventory(&[("usr/bin/app", f.clone()), ("usr/bin/app-helper", f.clone())]);
        let packages = [pkg("app", &["usr/bin/app", "usr/bin/app-helper"])];
        let reached = set(&["usr/bin/app"]);
        let kl = KeepList::default();
        let p = plan(&PlanInput {
            inventory: &inv,
            packages: &packages,
            reached: &reached,
            dynamic: &reached,
            keep_list: &kl,
            mandatory: false,
            granularity: Granularity::File,
        });
        assert!(p.keep.contains(Path::new("usr/bin/app")));
        assert!(!p.keep.contains(Path::new("usr/bin/app-helper")));
        assert!(p.removed_packages.is_empty(), "still partly needed, so it stays in the database");
    }

    #[test]
    fn keep_list_symlinks_and_hard_links_pull_in_their_targets() {
        let inv = inventory(&[
            ("lib", EntryKind::Directory),
            ("lib/libz.so.1", EntryKind::Symlink("libz.so.1.2".into())),
            ("lib/libz.so.1.2", EntryKind::File),
            ("opt/a", EntryKind::File),
            ("opt/b", EntryKind::HardLink("opt/a".into())),
            ("opt/other", EntryKind::File),
        ]);
        let kl = KeepList::parse("[keep]\npaths = [\"/lib/libz.so.1\", \"/opt/b\"]\n").unwrap();
        let none = BTreeSet::new();
        let p = plan(&PlanInput {
            inventory: &inv,
            packages: &[],
            reached: &none,
            dynamic: &none,
            keep_list: &kl,
            mandatory: false,
            granularity: Granularity::Package,
        });
        assert!(p.keep.contains(Path::new("lib/libz.so.1.2")), "symlink target");
        assert!(p.keep.contains(Path::new("opt/a")), "hard link original");
        assert!(!p.keep.contains(Path::new("opt/other")));
    }

    #[test]
    fn keep_list_parsing() {
        let k = KeepList::parse("[keep]\npaths = [\"/app/locales/**\"]\npackages = [\"tzdata\"]\n")
            .unwrap();
        assert_eq!(k.paths, ["app/locales/**"]);
        assert_eq!(k.packages, ["tzdata"]);
        assert_eq!(KeepList::parse("").unwrap(), KeepList::default());
        assert!(KeepList::parse("keep = 3").is_err());
    }
}
