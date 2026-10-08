//! The one advisory shape every feed is normalised into: a trimmed OSV record
//! (https://ossf.github.io/osv-schema/). `severity` and `cvss` are Bedrock
//! additions, resolved at ingest so `scan` never needs to know which feed a
//! record came from.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// CVSS v3 qualitative bands. 0.0 ("None") has no severity.
    pub fn from_cvss(score: f32) -> Option<Self> {
        match score {
            s if s >= 9.0 => Some(Self::Critical),
            s if s >= 7.0 => Some(Self::High),
            s if s >= 4.0 => Some(Self::Medium),
            s if s > 0.0 => Some(Self::Low),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Maps the free-text ratings feeds use ("moderate", "important", ...).
    pub fn from_label(label: &str) -> Option<Self> {
        match label.to_ascii_lowercase().as_str() {
            "low" | "unimportant" | "negligible" => Some(Self::Low),
            "medium" | "moderate" => Some(Self::Medium),
            "high" | "important" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Advisory {
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// CVSS v3 base score when the feed gave one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f32>,
    pub affected: Vec<Affected>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Affected {
    /// OSV ecosystem string: `PyPI`, `npm`, `Go`, `crates.io`, or a distro
    /// release: `Debian:12`, `Alpine:v3.20`, `Red Hat:9`.
    pub ecosystem: String,
    /// For Debian this is the *source* package, for Alpine the *origin*
    /// package, because that is how those trackers key their data.
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<Range>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Range {
    /// `SEMVER` or `ECOSYSTEM`. `GIT` ranges are dropped at ingest.
    #[serde(rename = "type")]
    pub kind: String,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Event {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduced: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_affected: Option<String>,
}

impl Range {
    /// `[introduced 0, fixed v]`, or open-ended when `fixed` is `None`.
    pub fn up_to(fixed: Option<&str>) -> Self {
        let mut events = vec![Event { introduced: Some("0".into()), ..Event::default() }];
        if let Some(f) = fixed {
            events.push(Event { fixed: Some(f.into()), ..Event::default() });
        }
        Range { kind: "ECOSYSTEM".into(), events }
    }
}

/// CVSS v3.0/v3.1 base score from a vector string, or `None` if it is not a
/// well-formed v3 vector.
pub fn cvss3_base(vector: &str) -> Option<f32> {
    let mut parts = vector.split('/');
    if !matches!(parts.next()?, "CVSS:3.0" | "CVSS:3.1") {
        return None;
    }
    let (mut av, mut ac, mut pr, mut ui, mut scope, mut c, mut i, mut a) =
        (None, None, None, None, None, None, None, None);
    for p in parts {
        let (k, v) = p.split_once(':')?;
        match k {
            "AV" => av = Some(v),
            "AC" => ac = Some(v),
            "PR" => pr = Some(v),
            "UI" => ui = Some(v),
            "S" => scope = Some(v),
            "C" => c = Some(v),
            "I" => i = Some(v),
            "A" => a = Some(v),
            _ => {} // temporal/environmental metrics don't affect the base score
        }
    }
    let changed = match scope? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let av = match av? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match ac? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (pr?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match ui? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |m: Option<&str>| match m? {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let iss = 1.0 - (1.0 - cia(c)?) * (1.0 - cia(i)?) * (1.0 - cia(a)?);
    let impact =
        if changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15) } else { 6.42 * iss };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploit = 8.22 * av * ac * pr * ui;
    let raw = if changed { 1.08 * (impact + exploit) } else { impact + exploit };
    Some(roundup(raw.min(10.0)) as f32)
}

/// CVSS 3.1 Appendix A "Roundup": smallest 1-decimal value >= x, immune to
/// float noise.
fn roundup(x: f64) -> f64 {
    let n = (x * 100_000.0).round() as i64;
    if n % 10_000 == 0 {
        n as f64 / 100_000.0
    } else {
        ((n / 10_000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_known_scores() {
        let s = |v| cvss3_base(v).unwrap();
        assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
        assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
        assert_eq!(s("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8);
        assert_eq!(s("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 6.5);
        assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0);
        assert_eq!(cvss3_base("CVSS:2.0/AV:N"), None);
        assert_eq!(cvss3_base("garbage"), None);
    }

    #[test]
    fn severity_bands() {
        assert_eq!(Severity::from_cvss(9.8), Some(Severity::Critical));
        assert_eq!(Severity::from_cvss(7.0), Some(Severity::High));
        assert_eq!(Severity::from_cvss(0.0), None);
        assert_eq!(Severity::from_label("Moderate"), Some(Severity::Medium));
    }
}
