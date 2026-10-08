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
        for n in &self.notes {
            let _ = writeln!(out, "note: {}", esc(n));
        }
        if !self.findings.is_empty() {
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
