//! Rewrites package databases so a removed package disappears from the pruned
//! image's own SBOM, not just from disk. Without this, `dpkg -l` and every
//! scanner would still report packages whose files are gone.
//!
//! rpm databases (SQLite or Berkeley DB) are not rewritten; the report notes it.
use std::collections::BTreeSet;

/// dpkg `status` file: stanzas separated by blank lines, first field `Package:`.
pub fn dpkg_status_without(text: &str, removed: &BTreeSet<&str>) -> String {
    drop_stanzas(text, |stanza| {
        stanza
            .lines()
            .find_map(|l| l.strip_prefix("Package:"))
            .map(str::trim)
            .is_some_and(|n| removed.contains(n))
    })
}

/// apk `installed` database: stanzas separated by blank lines, name in `P:`.
pub fn apk_installed_without(text: &str, removed: &BTreeSet<&str>) -> String {
    drop_stanzas(text, |stanza| {
        stanza
            .lines()
            .find_map(|l| l.strip_prefix("P:"))
            .map(str::trim)
            .is_some_and(|n| removed.contains(n))
    })
}

fn drop_stanzas(text: &str, drop: impl Fn(&str) -> bool) -> String {
    let kept: Vec<&str> = text.split("\n\n").filter(|s| !s.trim().is_empty() && !drop(s)).collect();
    let mut out = kept.join("\n\n");
    if !out.is_empty() && text.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_only_named_stanzas_and_keeps_the_rest_verbatim() {
        let status = "Package: keep\nVersion: 1\n\nPackage: gone\nVersion: 2\nDepends: x\n\nPackage: also-keep\nVersion: 3\n";
        let out = dpkg_status_without(status, &BTreeSet::from(["gone"]));
        assert_eq!(out, "Package: keep\nVersion: 1\n\nPackage: also-keep\nVersion: 3\n");
        assert_eq!(dpkg_status_without(status, &BTreeSet::new()), status);
    }

    #[test]
    fn apk_database() {
        let db = "P:musl\nV:1\n\nP:curl\nV:2\nF:usr/bin\nR:curl\n\n";
        let out = apk_installed_without(db, &BTreeSet::from(["curl"]));
        assert!(out.contains("P:musl") && !out.contains("curl"));
        assert!(out.ends_with('\n'));
    }
}
