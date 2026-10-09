//! Matches SBOM packages against advisories.
//!
//! Precedence rule (BEDROCK_SPEC.md 5.4): a distribution package is only ever
//! matched against its own distribution's feed. Distros backport fixes without
//! changing the upstream version, so an upstream range from OSV would flag a
//! patched `1.2.3-4+deb12u1` as vulnerable. Language packages (npm, PyPI) match
//! against OSV. A distro with no feed (Ubuntu, Fedora, ...) is reported as not
//! assessed, never guessed at.
use super::advisory::{Advisory, Affected, Event};
use super::db::VulnerabilityDb;
use super::version::{compare, Scheme};
use crate::report::{Finding, PackageRef};
use crate::sbom::Package;
use crate::Result;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    /// Packages that could not be assessed, and why.
    pub notes: Vec<String>,
}

/// Loads only the snapshot sources the packages need, then matches.
pub fn scan(packages: &[Package], db: &VulnerabilityDb) -> Result<ScanOutcome> {
    let plan = Plan::new(packages);
    let wanted = plan.sources();
    let advisories = db.load_sources(|s| wanted.contains(s))?;
    Ok(plan.run(&advisories))
}

struct Target<'a> {
    pkg: &'a Package,
    ecosystem: String,
    scheme: Scheme,
    /// Names to look the package up under: source/origin first for distros.
    names: Vec<String>,
}

struct Plan<'a> {
    targets: Vec<Target<'a>>,
    notes: Vec<String>,
}

impl<'a> Plan<'a> {
    fn new(packages: &'a [Package]) -> Self {
        let mut targets = Vec::new();
        let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
        for pkg in packages {
            match target(pkg) {
                Ok(t) => targets.push(t),
                Err(why) => *skipped.entry(why).or_default() += 1,
            }
        }
        let notes = skipped
            .into_iter()
            .map(|(why, n)| format!("{n} packages not assessed: {why}"))
            .collect();
        Plan { targets, notes }
    }

    fn sources(&self) -> BTreeSet<String> {
        self.targets.iter().map(|t| source_for(&t.ecosystem)).collect()
    }

    fn run(self, advisories: &[Advisory]) -> ScanOutcome {
        let mut index: HashMap<(String, String), Vec<(usize, usize)>> = HashMap::new();
        for (ai, adv) in advisories.iter().enumerate() {
            for (xi, aff) in adv.affected.iter().enumerate() {
                index
                    .entry((aff.ecosystem.clone(), normalise(&aff.ecosystem, &aff.name)))
                    .or_default()
                    .push((ai, xi));
            }
        }

        // A release the snapshot has no data for (an EOL Debian, say) would
        // otherwise look clean. Say so instead.
        let mut no_data: BTreeMap<&str, usize> = BTreeMap::new();
        for t in &self.targets {
            if !index.keys().any(|(eco, _)| *eco == t.ecosystem) {
                *no_data.entry(&t.ecosystem).or_default() += 1;
            }
        }
        let mut notes = self.notes.clone();
        notes.extend(no_data.into_iter().map(|(eco, n)| {
            format!("{n} packages not assessed: the advisory snapshot has no data for {eco}")
        }));

        // (purl, canonical id) -> merged finding
        let mut merged: BTreeMap<(String, String), Finding> = BTreeMap::new();
        for t in &self.targets {
            for name in &t.names {
                let Some(entries) = index.get(&(t.ecosystem.clone(), name.clone())) else {
                    continue;
                };
                for &(ai, xi) in entries {
                    let adv = &advisories[ai];
                    let aff = &adv.affected[xi];
                    let Some(fixed) = affected_by(t.scheme, &t.pkg.version, aff) else { continue };
                    let id = canonical_id(adv);
                    let finding =
                        merged.entry((t.pkg.purl.clone(), id.clone())).or_insert_with(|| Finding {
                            id: id.clone(),
                            aliases: vec![],
                            severity: None,
                            cvss: None,
                            package: PackageRef {
                                name: t.pkg.name.clone(),
                                version: t.pkg.version.clone(),
                                purl: t.pkg.purl.clone(),
                            },
                            fixed_version: None,
                            fixed_package: None,
                        });
                    for a in std::iter::once(&adv.id).chain(&adv.aliases) {
                        if *a != finding.id && !finding.aliases.contains(a) {
                            finding.aliases.push(a.clone());
                        }
                    }
                    finding.severity = finding.severity.max(adv.severity);
                    finding.cvss = match (finding.cvss, adv.cvss) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                    // Several advisories can describe one vulnerability: the
                    // real fix is the highest of their fixes.
                    if let Some(f) = fixed {
                        let higher = finding
                            .fixed_version
                            .as_deref()
                            .is_none_or(|cur| compare(t.scheme, &f, cur) == Ordering::Greater);
                        if higher {
                            finding.fixed_version = Some(f);
                            finding.fixed_package = Some(aff.name.clone());
                        }
                    }
                }
            }
        }
        let mut findings: Vec<Finding> = merged
            .into_values()
            .map(|mut f| {
                f.aliases.sort();
                f
            })
            .collect();
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.package.name.cmp(&b.package.name))
                .then_with(|| a.id.cmp(&b.id))
        });
        ScanOutcome { findings, notes }
    }
}

/// Which snapshot source file holds an ecosystem's advisories.
fn source_for(ecosystem: &str) -> String {
    match ecosystem.split(':').next().unwrap_or(ecosystem) {
        "Debian" => "debian".into(),
        "Alpine" => "alpine".into(),
        "Red Hat" => "redhat".into(),
        other => format!("osv-{other}"),
    }
}

/// PyPI names compare case-insensitively with `-`, `_` and `.` equivalent (PEP 503).
fn normalise(ecosystem: &str, name: &str) -> String {
    if ecosystem == "PyPI" {
        let mut out = String::with_capacity(name.len());
        for c in name.chars().map(|c| c.to_ascii_lowercase()) {
            if matches!(c, '-' | '_' | '.') {
                if !out.ends_with('-') {
                    out.push('-');
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        name.to_string()
    }
}

/// `Err` carries the reason the package cannot be assessed, used as a note key.
fn target(pkg: &Package) -> std::result::Result<Target<'_>, String> {
    if pkg.version.is_empty() || pkg.version == "unknown" {
        return Err("version could not be determined".into());
    }
    let rest = pkg.purl.strip_prefix("pkg:").ok_or("not a PURL")?;
    let (ty, _) = rest.split_once('/').ok_or("not a PURL")?;
    let distro = pkg
        .purl
        .split_once('?')
        .and_then(|(_, q)| q.split('&').find_map(|kv| kv.strip_prefix("distro=")))
        .and_then(|d| d.split_once('-'))
        .map(|(id, v)| (id.to_string(), v.to_string()));
    let source_or_name = || pkg.source.clone().unwrap_or_else(|| pkg.name.clone());
    let major = |v: &str| v.split('.').next().unwrap_or(v).to_string();

    let (ecosystem, scheme, names) = match ty {
        "npm" => ("npm".to_string(), Scheme::Semver, vec![pkg.name.clone()]),
        "pypi" => ("PyPI".to_string(), Scheme::Pep440, vec![normalise("PyPI", &pkg.name)]),
        "golang" => ("Go".to_string(), Scheme::Semver, vec![pkg.name.clone()]),
        "cargo" => ("crates.io".to_string(), Scheme::Semver, vec![pkg.name.clone()]),
        "deb" | "apk" | "rpm" => {
            let Some((id, ver)) = distro else {
                return Err(format!("{ty} packages with no distro release in os-release"));
            };
            let name_list;
            let (eco, scheme) = match (ty, id.as_str()) {
                ("deb", "debian") => {
                    name_list = vec![source_or_name()];
                    (format!("Debian:{}", major(&ver)), Scheme::Dpkg)
                }
                ("apk", "alpine") => {
                    name_list = vec![source_or_name()];
                    let mut parts = ver.split('.');
                    let (a, b) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                    (format!("Alpine:v{a}.{b}"), Scheme::Apk)
                }
                // Rebuilds of RHEL keep its release tags (`el9_3`) and fix versions.
                ("rpm", "rhel" | "centos" | "rocky" | "almalinux") => {
                    let mut n = vec![pkg.name.clone()];
                    n.extend(pkg.source.clone().filter(|s| *s != pkg.name));
                    name_list = n;
                    (format!("Red Hat:{}", major(&ver)), Scheme::Rpm)
                }
                _ => return Err(format!("no advisory feed for {id}-{ver} ({ty})")),
            };
            (eco, scheme, name_list)
        }
        _ => return Err(format!("no advisory feed for {ty} packages")),
    };
    Ok(Target { pkg, ecosystem, scheme, names })
}

fn canonical_id(adv: &Advisory) -> String {
    if adv.id.starts_with("CVE-") {
        return adv.id.clone();
    }
    adv.aliases.iter().find(|a| a.starts_with("CVE-")).unwrap_or(&adv.id).clone()
}

/// `None` when `version` is not affected. `Some(fix)` when it is, with the
/// nearest fixed version above it if the advisory names one.
fn affected_by(scheme: Scheme, version: &str, aff: &Affected) -> Option<Option<String>> {
    let mut hit = aff.versions.iter().any(|v| compare(scheme, v, version) == Ordering::Equal);
    let mut fixes: Vec<&str> = Vec::new();
    for range in &aff.ranges {
        let s = if range.kind == "SEMVER" { Scheme::Semver } else { scheme };
        let key = |e: &Event| -> String {
            e.introduced
                .clone()
                .or_else(|| e.fixed.clone())
                .or_else(|| e.last_affected.clone())
                .unwrap_or_default()
        };
        let mut events: Vec<&Event> = range.events.iter().collect();
        // Ascending by version; `introduced: "0"` is the floor.
        events.sort_by(|a, b| {
            match (a.introduced.as_deref() == Some("0"), b.introduced.as_deref() == Some("0")) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => compare(s, &key(a), &key(b)),
            }
        });
        let mut in_range = false;
        for e in &events {
            if let Some(i) = &e.introduced {
                if i == "0" || compare(s, version, i) != Ordering::Less {
                    in_range = true;
                }
            } else if let Some(f) = &e.fixed {
                if compare(s, version, f) != Ordering::Less {
                    in_range = false;
                }
            } else if let Some(l) = &e.last_affected {
                if compare(s, version, l) == Ordering::Greater {
                    in_range = false;
                }
            }
        }
        if in_range {
            hit = true;
            fixes.extend(
                range
                    .events
                    .iter()
                    .filter_map(|e| e.fixed.as_deref())
                    .filter(|f| compare(s, f, version) == Ordering::Greater),
            );
        }
    }
    hit.then(|| fixes.into_iter().min_by(|a, b| compare(scheme, a, b)).map(String::from))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::advisory::{Range, Severity};

    fn pkg(name: &str, version: &str, purl: &str, source: Option<&str>) -> Package {
        Package {
            name: name.into(),
            version: version.into(),
            architecture: None,
            source: source.map(String::from),
            purl: purl.into(),
            files: vec![],
        }
    }

    fn adv(
        id: &str,
        aliases: &[&str],
        sev: Option<Severity>,
        eco: &str,
        name: &str,
        fixed: Option<&str>,
    ) -> Advisory {
        Advisory {
            id: id.into(),
            aliases: aliases.iter().map(|s| s.to_string()).collect(),
            severity: sev,
            cvss: None,
            affected: vec![Affected {
                ecosystem: eco.into(),
                name: name.into(),
                ranges: vec![Range::up_to(fixed)],
                versions: vec![],
            }],
        }
    }

    fn run(packages: &[Package], advisories: &[Advisory]) -> ScanOutcome {
        Plan::new(packages).run(advisories)
    }

    #[test]
    fn debian_backport_is_not_flagged() {
        let advs = [adv(
            "CVE-1",
            &[],
            Some(Severity::High),
            "Debian:12",
            "openssl",
            Some("3.0.11-1~deb12u2"),
        )];
        let old = pkg(
            "libssl3",
            "3.0.9-1",
            "pkg:deb/debian/libssl3@3.0.9-1?arch=amd64&distro=debian-12",
            Some("openssl"),
        );
        let patched = pkg(
            "libssl3",
            "3.0.11-1~deb12u2",
            "pkg:deb/debian/libssl3@x?distro=debian-12",
            Some("openssl"),
        );
        let out = run(&[old, patched], &advs);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].package.version, "3.0.9-1");
        assert_eq!(out.findings[0].fixed_version.as_deref(), Some("3.0.11-1~deb12u2"));
        assert_eq!(out.findings[0].fixed_package.as_deref(), Some("openssl"));
    }

    #[test]
    fn distro_packages_ignore_osv_ecosystems() {
        // An npm-style advisory for the same name must not hit a deb package.
        let advs = [adv("GHSA-1", &["CVE-9"], None, "npm", "libssl3", Some("9.9.9"))];
        let p = pkg("libssl3", "1.0", "pkg:deb/debian/libssl3@1.0?distro=debian-12", None);
        assert!(run(&[p], &advs).findings.is_empty());
    }

    #[test]
    fn release_missing_from_snapshot_is_noted() {
        let advs = [adv("CVE-1", &[], None, "Debian:12", "foo", Some("2.0"))];
        let p = pkg("foo", "1.0", "pkg:deb/debian/foo@1.0?distro=debian-11", None);
        let out = run(&[p], &advs);
        assert!(out.findings.is_empty());
        assert!(out.notes.iter().any(|n| n.contains("no data for Debian:11")), "{:?}", out.notes);
    }

    #[test]
    fn unsupported_distro_and_unknown_version_are_noted_not_guessed() {
        let u = pkg("bash", "5.1", "pkg:deb/ubuntu/bash@5.1?distro=ubuntu-22.04", None);
        let n = pkg("left-pad", "unknown", "pkg:npm/left-pad@unknown", None);
        let out = run(&[u, n], &[]);
        assert!(out.notes.iter().any(|n| n.contains("no advisory feed for ubuntu-22.04")));
        assert!(out.notes.iter().any(|n| n.contains("version could not be determined")));
    }

    #[test]
    fn pypi_aliases_merge_into_one_finding_and_names_normalise() {
        let advs = [
            adv(
                "GHSA-x",
                &["CVE-2023-1", "PYSEC-1"],
                Some(Severity::Medium),
                "PyPI",
                "Foo_Bar",
                Some("2.0.0"),
            ),
            adv("PYSEC-1", &["CVE-2023-1"], Some(Severity::High), "PyPI", "foo-bar", Some("2.0.1")),
        ];
        let p = pkg("foo.bar", "1.9", "pkg:pypi/foo-bar@1.9", None);
        let out = run(&[p], &advs);
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.id, "CVE-2023-1");
        assert_eq!(f.aliases, ["GHSA-x", "PYSEC-1"]);
        assert_eq!(f.severity, Some(Severity::High));
        assert_eq!(f.fixed_version.as_deref(), Some("2.0.1"));
    }

    #[test]
    fn apk_matches_origin_and_compares_with_apk_rules() {
        let advs = [adv("CVE-2", &[], None, "Alpine:v3.20", "openssl", Some("3.3.2-r0"))];
        let sub = pkg(
            "libssl3",
            "3.3.1-r3",
            "pkg:apk/alpine/libssl3@3.3.1-r3?distro=alpine-3.20.3",
            Some("openssl"),
        );
        let fixed = pkg(
            "libssl3",
            "3.3.10-r0",
            "pkg:apk/alpine/libssl3@3.3.10-r0?distro=alpine-3.20.3",
            Some("openssl"),
        );
        let out = run(&[sub, fixed], &advs);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].package.version, "3.3.1-r3");
    }

    #[test]
    fn rpm_matches_by_binary_or_source_name() {
        let advs = [adv(
            "CVE-3",
            &[],
            Some(Severity::High),
            "Red Hat:9",
            "openssl",
            Some("1:3.0.7-24.el9"),
        )];
        let p = pkg(
            "openssl-libs",
            "1:3.0.1-1.el9",
            "pkg:rpm/rhel/openssl-libs@3.0.1-1.el9?distro=rhel-9.3",
            Some("openssl"),
        );
        assert_eq!(run(&[p], &advs).findings.len(), 1);
        let fixed = pkg(
            "openssl-libs",
            "1:3.0.7-24.el9",
            "pkg:rpm/rhel/openssl-libs@x?distro=rhel-9.3",
            Some("openssl"),
        );
        assert!(run(&[fixed], &advs).findings.is_empty());
    }

    #[test]
    fn open_ended_range_has_no_fix_and_last_affected_is_inclusive() {
        let open = adv("CVE-4", &[], None, "Debian:12", "foo", None);
        let p = pkg("foo", "1.0", "pkg:deb/debian/foo@1.0?distro=debian-12", None);
        let out = run(std::slice::from_ref(&p), &[open]);
        assert_eq!(out.findings.len(), 1);
        assert!(out.findings[0].fixed_version.is_none());

        let mut a = adv("CVE-5", &[], None, "npm", "bar", None);
        a.affected[0].ranges = vec![Range {
            kind: "SEMVER".into(),
            events: vec![
                Event { introduced: Some("1.0.0".into()), ..Event::default() },
                Event { last_affected: Some("1.5.0".into()), ..Event::default() },
            ],
        }];
        let at = |v: &str| pkg("bar", v, &format!("pkg:npm/bar@{v}"), None);
        assert_eq!(run(&[at("1.5.0"), at("1.10.0"), at("0.9.0")], &[a]).findings.len(), 1);
    }
}
