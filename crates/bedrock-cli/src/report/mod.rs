//! The report model (BEDROCK_SPEC.md 5.9). `scan` fills the parts it knows;
//! `slim` adds `output`, `delta`, `trace`, `removals`, `verify` and `attest`
//! as new optional fields. Within a major `schema_version` fields are only
//! ever added, never renamed or removed, so `report` can re-render any older
//! saved report.
pub mod sarif;

use crate::vuln::Severity;
use serde::{Deserialize, Serialize};
use std::fmt::Write;

pub const SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub tool_version: String,
    pub timestamp: String,
    pub input: ImageSummary,
    /// Advisory snapshot the findings came from; CVE counts change daily.
    pub snapshot: SnapshotRef,
    pub findings: Vec<Finding>,
    /// Things the reader needs to trust the counts, e.g. packages that could
    /// not be assessed because their distribution has no advisory feed.
    pub notes: Vec<String>,
    // The fields below are filled by `slim` and absent from a `scan` report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<ImageSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<Delta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<TraceSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removals: Vec<Removal>,
    /// Kept although no syscall touched them: the user's next target for a stricter run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained_unreached: Vec<Retained>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<Verify>,
    /// How `slim` was run; the source of the provenance attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildInfo>,
}

/// The resolved invocation of `slim`, enough to describe how the output was made.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    pub command_line: Vec<String>,
    /// `sha256:...` of the workload script or request file (none for a timed run).
    pub workload_digest: Option<String>,
    pub keep_list_digest: Option<String>,
    pub granularity: String,
    pub preserve_layers: bool,
    pub mandatory: bool,
    pub verify: bool,
    pub allow_partial_trace: bool,
    /// `sha256:...` of the Bedrock executable that ran.
    pub bedrock_digest: Option<String>,
}

/// Output minus input. Negative numbers are reductions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delta {
    pub size_bytes: i64,
    pub size_pct: f64,
    pub packages: i64,
    pub findings_by_severity: SeverityDeltas,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityDeltas {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub unknown: i64,
}

impl Delta {
    pub fn between(input: &ImageSummary, output: &ImageSummary) -> Self {
        let d = |a: usize, b: usize| b as i64 - a as i64;
        let (i, o) = (&input.findings_by_severity, &output.findings_by_severity);
        let size_bytes = output.size_bytes as i64 - input.size_bytes as i64;
        Self {
            size_bytes,
            size_pct: if input.size_bytes == 0 {
                0.0
            } else {
                (size_bytes as f64 / input.size_bytes as f64 * 1000.0).round() / 10.0
            },
            packages: d(input.packages, output.packages),
            findings_by_severity: SeverityDeltas {
                critical: d(i.critical, o.critical),
                high: d(i.high, o.high),
                medium: d(i.medium, o.medium),
                low: d(i.low, o.low),
                unknown: d(i.unknown, o.unknown),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummary {
    pub workload_kind: String,
    pub duration_ms: u64,
    pub reached_files: usize,
    pub total_files: usize,
    pub reached_packages: usize,
    pub total_packages: usize,
    pub partially_reached_packages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Removal {
    /// `package` or `file`.
    pub kind: String,
    pub name: String,
    /// `no_file_reached`, `only_docs_reached` or `not_in_closure`.
    pub reason: String,
    /// Findings that went away with it.
    pub findings_removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retained {
    pub name: String,
    /// `keep_list`, `mandatory` or `closure`.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verify {
    /// `pass`, `fail` or `skipped`.
    pub status: String,
    /// Paths the pruned run needed and could not find (set on failure).
    pub missed_paths: Vec<String>,
    /// Paths the pruned run looked for and did not find, though it passed.
    pub enoent_warnings: Vec<String>,
    /// What differed from the original run, in words.
    #[serde(default)]
    pub mismatches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSummary {
    pub reference: String,
    /// The image config digest (the "image ID").
    pub digest: String,
    pub platform: String,
    pub size_bytes: u64,
    pub layers: usize,
    pub packages: usize,
    pub findings_by_severity: SeverityCounts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
}

impl SeverityCounts {
    pub fn of(findings: &[Finding]) -> Self {
        let mut c = Self::default();
        for f in findings {
            match f.severity {
                Some(Severity::Critical) => c.critical += 1,
                Some(Severity::High) => c.high += 1,
                Some(Severity::Medium) => c.medium += 1,
                Some(Severity::Low) => c.low += 1,
                None => c.unknown += 1,
            }
        }
        c
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRef {
    pub digest: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// The CVE id when there is one, else the advisory's own id.
    pub id: String,
    /// Every other id this vulnerability is known by (GHSA, PYSEC, ...).
    pub aliases: Vec<String>,
    /// CVSS v3 band if the feed gave a score, else the feed's own rating.
    pub severity: Option<Severity>,
    pub cvss: Option<f32>,
    pub package: PackageRef,
    /// Nearest fix in the same ecosystem or distribution release.
    pub fixed_version: Option<String>,
    /// Package that carries the fix (the source/origin package for distros).
    pub fixed_package: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageRef {
    pub name: String,
    pub version: String,
    pub purl: String,
}

impl Report {
    pub fn new(
        input: ImageSummary,
        snapshot: SnapshotRef,
        findings: Vec<Finding>,
        notes: Vec<String>,
    ) -> Self {
        let mut input = input;
        input.findings_by_severity = SeverityCounts::of(&findings);
        Self {
            schema_version: SCHEMA_VERSION.into(),
            tool_version: env!("CARGO_PKG_VERSION").into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            input,
            snapshot,
            findings,
            notes,
            output: None,
            delta: None,
            trace: None,
            removals: Vec::new(),
            retained_unreached: Vec::new(),
            verify: None,
            build: None,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serialises")
    }

    /// Findings at or above `threshold`. Unrated findings never count: a
    /// gate that fails on "unknown" would fail on every Debian "unimportant".
    pub fn count_at_least(&self, threshold: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity.is_some_and(|s| s >= threshold)).count()
    }

    /// Plain-text rendering. Everything that came from inside the image is
    /// escaped so a hostile package name cannot inject terminal sequences.
    pub fn to_terminal(&self) -> String {
        use crate::escape_control as esc;
        let c = &self.input.findings_by_severity;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Image    {}  {}  {} packages",
            esc(&self.input.reference),
            esc(&self.input.digest),
            self.input.packages
        );
        let _ = writeln!(
            out,
            "Findings {} critical  {} high  {} medium  {} low  {} unrated",
            c.critical, c.high, c.medium, c.low, c.unknown
        );
        let _ = writeln!(
            out,
            "Snapshot {} ({})",
            &self.snapshot.digest[..12.min(self.snapshot.digest.len())],
            self.snapshot.updated_at
        );
        if let Some(o) = &self.output {
            let oc = &o.findings_by_severity;
            let _ = writeln!(
                out,
                "Output   {}  {}  {} packages  {} critical  {} high  {} medium  {} low",
                esc(&o.reference),
                esc(&o.digest),
                o.packages,
                oc.critical,
                oc.high,
                oc.medium,
                oc.low
            );
            if let Some(d) = &self.delta {
                let f = &d.findings_by_severity;
                let _ = writeln!(
                    out,
                    "Delta    {:+.1}% size ({} -> {} bytes)  {:+} packages  findings {:+} critical  {:+} high  {:+} medium  {:+} low",
                    d.size_pct, self.input.size_bytes, o.size_bytes, d.packages, f.critical, f.high, f.medium, f.low
                );
            }
        }
        if let Some(t) = &self.trace {
            let _ = writeln!(
                out,
                "Trace    {} ({:.1} s)  reached {}/{} files, {}/{} packages, {} partially",
                t.workload_kind,
                t.duration_ms as f64 / 1000.0,
                t.reached_files,
                t.total_files,
                t.reached_packages,
                t.total_packages,
                t.partially_reached_packages.len()
            );
        }
        if let Some(v) = &self.verify {
            let _ = writeln!(
                out,
                "Verify   {}  {} missed paths, {} ENOENT warnings",
                v.status.to_uppercase(),
                v.missed_paths.len(),
                v.enoent_warnings.len()
            );
            for m in &v.mismatches {
                let _ = writeln!(out, "  mismatch: {}", esc(m));
            }
            for p in v.missed_paths.iter().take(20) {
                let _ = writeln!(
                    out,
                    "  missing: {}   (keep it with: paths = [\"{}\"])",
                    esc(p),
                    esc(p)
                );
            }
        }
        if !self.retained_unreached.is_empty() {
            let names: Vec<String> = self
                .retained_unreached
                .iter()
                .take(12)
                .map(|r| format!("{} ({})", esc(&r.name), r.reason))
                .collect();
            let more = self.retained_unreached.len().saturating_sub(12);
            let _ = writeln!(
                out,
                "Retained but unreached: {}{}",
                names.join(", "),
                if more > 0 { format!(", and {more} more") } else { String::new() }
            );
        }
        if !self.removals.is_empty() {
            let mut rows: Vec<&Removal> = self.removals.iter().collect();
            rows.sort_by(|a, b| {
                b.findings_removed
                    .len()
                    .cmp(&a.findings_removed.len())
                    .then(b.kind.cmp(&a.kind)) // packages before files
                    .then(a.name.cmp(&b.name))
            });
            let _ = writeln!(out, "\nRemoved {} items; most findings removed first:", rows.len());
            for r in rows.iter().take(20) {
                let _ = writeln!(
                    out,
                    "  {:<8} {:<40} {:<18} {} findings",
                    r.kind,
                    esc(&r.name),
                    r.reason,
                    r.findings_removed.len()
                );
            }
        }
        for n in &self.notes {
            let _ = writeln!(out, "note: {}", esc(n));
        }
        if !self.findings.is_empty() && self.output.is_none() {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{:<9} {:<22} {:<28} {:<22} FIXED IN",
                "SEVERITY", "ID", "PACKAGE", "VERSION"
            );
            for f in &self.findings {
                let sev = f.severity.map_or("unrated", |s| s.as_str());
                let _ = writeln!(
                    out,
                    "{:<9} {:<22} {:<28} {:<22} {}",
                    sev,
                    esc(&f.id),
                    esc(&f.package.name),
                    esc(&f.package.version),
                    f.fixed_version.as_deref().map_or("-".into(), esc)
                );
            }
        }
        out
    }
}
