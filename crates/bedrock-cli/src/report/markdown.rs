//! Markdown rendering of a report, for pull request comments and tickets.
use super::{Removal, Report};
use crate::escape_control;
use std::fmt::Write;

/// How many rows of the long tables a Markdown report prints.
const MAX_ROWS: usize = 40;

/// Text safe inside a table cell: control characters escaped, pipes and
/// backticks neutralised, so image-derived names cannot break the table.
fn cell(s: &str) -> String {
    escape_control(s).replace('|', "\\|").replace('`', "'")
}

fn bytes(n: u64) -> String {
    format!("{:.1} MB", n as f64 / 1_048_576.0)
}

pub fn to_markdown(r: &Report) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "# Bedrock report\n");
    let _ = writeln!(
        o,
        "Image `{}` ({}), generated {} by Bedrock {}. Advisory snapshot `{}`.\n",
        cell(&r.input.reference),
        cell(&r.input.platform),
        r.timestamp,
        r.tool_version,
        &r.snapshot.digest[..r.snapshot.digest.len().min(12)]
    );

    let i = &r.input;
    let ic = &i.findings_by_severity;
    match (&r.output, &r.delta) {
        (Some(out), Some(d)) => {
            let oc = &out.findings_by_severity;
            let f = &d.findings_by_severity;
            let _ = writeln!(o, "| | Before | After | Change |\n|---|---:|---:|---:|");
            let _ = writeln!(
                o,
                "| Size | {} | {} | {:+.1}% |",
                bytes(i.size_bytes),
                bytes(out.size_bytes),
                d.size_pct
            );
            let _ = writeln!(o, "| Layers | {} | {} | |", i.layers, out.layers);
            let _ =
                writeln!(o, "| Packages | {} | {} | {:+} |", i.packages, out.packages, d.packages);
            let _ =
                writeln!(o, "| Critical | {} | {} | {:+} |", ic.critical, oc.critical, f.critical);
            let _ = writeln!(o, "| High | {} | {} | {:+} |", ic.high, oc.high, f.high);
            let _ = writeln!(o, "| Medium | {} | {} | {:+} |", ic.medium, oc.medium, f.medium);
            let _ = writeln!(o, "| Low | {} | {} | {:+} |", ic.low, oc.low, f.low);
            let _ =
                writeln!(o, "| Unrated | {} | {} | {:+} |\n", ic.unknown, oc.unknown, f.unknown);
        }
        _ => {
            let _ = writeln!(
                o,
                "{} packages. Findings: {} critical, {} high, {} medium, {} low, {} unrated.\n",
                i.packages, ic.critical, ic.high, ic.medium, ic.low, ic.unknown
            );
        }
    }

    if let Some(t) = &r.trace {
        let _ = writeln!(
            o,
            "**Trace.** {} workload, {:.1} s. Reached {}/{} files and {}/{} packages ({} only in part).\n",
            t.workload_kind,
            t.duration_ms as f64 / 1000.0,
            t.reached_files,
            t.total_files,
            t.reached_packages,
            t.total_packages,
            t.partially_reached_packages.len()
        );
    }
    if let Some(v) = &r.verify {
        let _ = writeln!(o, "**Verify: {}.**", v.status.to_uppercase());
        for m in &v.mismatches {
            let _ = writeln!(o, "- Mismatch: {}", cell(m));
        }
        for p in &v.missed_paths {
            let _ =
                writeln!(o, "- Missing: `{}`. Keep it with `paths = [\"{}\"]`", cell(p), cell(p));
        }
        if !v.enoent_warnings.is_empty() {
            let _ = writeln!(
                o,
                "- {} paths were looked up and not found (warnings).",
                v.enoent_warnings.len()
            );
        }
        let _ = writeln!(o);
    }

    if !r.removals.is_empty() {
        let mut rows: Vec<&Removal> = r.removals.iter().collect();
        rows.sort_by(|a, b| {
            b.findings_removed
                .len()
                .cmp(&a.findings_removed.len())
                .then(b.kind.cmp(&a.kind))
                .then(a.name.cmp(&b.name))
        });
        let _ = writeln!(o, "## Removed ({})\n", rows.len());
        let _ = writeln!(o, "| Kind | Name | Reason | Findings removed |\n|---|---|---|---|");
        for x in rows.iter().take(MAX_ROWS) {
            let ids =
                x.findings_removed.iter().take(6).map(|s| cell(s)).collect::<Vec<_>>().join(", ");
            let more = x.findings_removed.len().saturating_sub(6);
            let _ = writeln!(
                o,
                "| {} | `{}` | {} | {}{} |",
                x.kind,
                cell(&x.name),
                x.reason,
                ids,
                if more > 0 { format!(" and {more} more") } else { String::new() }
            );
        }
        if rows.len() > MAX_ROWS {
            let _ = writeln!(o, "\n{} more rows are in the JSON report.", rows.len() - MAX_ROWS);
        }
        let _ = writeln!(o);
    }

    if !r.retained_unreached.is_empty() {
        let _ = writeln!(o, "## Kept although never touched ({})\n", r.retained_unreached.len());
        for x in r.retained_unreached.iter().take(MAX_ROWS) {
            let _ = writeln!(o, "- `{}` ({})", cell(&x.name), x.reason);
        }
        if r.retained_unreached.len() > MAX_ROWS {
            let _ = writeln!(o, "- and {} more", r.retained_unreached.len() - MAX_ROWS);
        }
        let _ = writeln!(o);
    }

    if r.output.is_none() && !r.findings.is_empty() {
        let _ = writeln!(o, "## Findings ({})\n", r.findings.len());
        let _ =
            writeln!(o, "| Severity | ID | Package | Version | Fixed in |\n|---|---|---|---|---|");
        for f in r.findings.iter().take(MAX_ROWS * 5) {
            let _ = writeln!(
                o,
                "| {} | {} | `{}` | `{}` | {} |",
                f.severity.map_or("unrated", |s| s.as_str()),
                cell(&f.id),
                cell(&f.package.name),
                cell(&f.package.version),
                f.fixed_version.as_deref().map_or("none".into(), |v| format!("`{}`", cell(v)))
            );
        }
        if r.findings.len() > MAX_ROWS * 5 {
            let _ = writeln!(
                o,
                "\n{} more findings are in the JSON report.",
                r.findings.len() - MAX_ROWS * 5
            );
        }
        let _ = writeln!(o);
    }

    if !r.notes.is_empty() {
        let _ = writeln!(o, "## Notes\n");
        for n in &r.notes {
            let _ = writeln!(o, "- {}", cell(n));
        }
    }
    o
}
