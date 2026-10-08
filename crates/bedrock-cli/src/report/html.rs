//! Single-file HTML report (BEDROCK_SPEC.md 7.6). No scripts, no external
//! requests, no fonts to download: it opens offline, attaches to a ticket, and
//! passes any content security policy. Severity is drawn as a shape as well as a
//! colour so a monochrome print still reads. Everything that came from the
//! image is escaped.
use super::{Finding, Removal, Report};
use crate::escape_control;
use crate::vuln::Severity;
use std::collections::HashMap;
use std::fmt::Write;

/// Rows printed per long table before the rest is left to the JSON report.
const MAX_REMOVALS: usize = 400;
const MAX_FINDINGS: usize = 1500;

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in escape_control(s).chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn mb(n: u64) -> String {
    format!("{:.1} MB", n as f64 / 1_048_576.0)
}

fn sev_name(s: Option<Severity>) -> &'static str {
    s.map_or("unrated", |s| s.as_str())
}

/// Shape plus word, so severity never depends on colour alone.
fn sev(s: Option<Severity>) -> String {
    format!("<span class=\"sev sev-{0}\" aria-hidden=\"true\"></span><span>{0}</span>", sev_name(s))
}

fn explain(reason: &str) -> &'static str {
    match reason {
        "no_file_reached" => "No file of this package was opened, executed or mapped during the trace, and no reached program needs one.",
        "only_docs_reached" => "Only documentation was touched (for example by a directory listing). Nothing the program runs.",
        "not_in_closure" => "Not reached by the trace and not a dependency of anything that was.",
        _ => "",
    }
}

const CSS: &str = r#"
:root{--ground:#F3F1EC;--ink:#1B1D21;--stone:#8C877D;--muted:#5E5A52;--seam:#2B5F73;--crit:#8E2A2A;--warn:#9A6412;--pass:#2F6B3C;--rule:#D6D2C8;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--ground:#17191C;--ink:#E8E6E1;--stone:#8A8578;--muted:#A29D91;--seam:#6FB1C7;--crit:#E07A7A;--warn:#E5A94A;--pass:#6FBE7F;--rule:#34373B}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--ground);color:var(--ink);font:16px/1.55 "Seravek","Gill Sans Nova","Ubuntu","Calibri","DejaVu Sans","Segoe UI",sans-serif}
code,.mono,td.num,th.num,.digest{font-family:ui-monospace,"Cascadia Code","Source Code Pro",Menlo,Consolas,"DejaVu Sans Mono",monospace;font-variant-numeric:slashed-zero tabular-nums;font-feature-settings:"zero" 1}
main{max-width:64rem;margin:0 auto;padding:2.5rem 1.25rem 4rem}
h1,h2{text-wrap:balance}
h1{font-size:1.75rem;line-height:1.2;margin:0 0 .25rem;letter-spacing:-.01em}
h2{font-size:1.15rem;margin:2.75rem 0 .75rem;padding-top:1rem;border-top:1px solid var(--rule)}
p{margin:.5rem 0;max-width:68ch}
a{color:var(--seam)}
.meta{color:var(--muted);margin:0}
.meta code{color:var(--ink);overflow-wrap:anywhere}
.digest{overflow-wrap:anywhere;font-size:.85em}
td code,li code{overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;margin:.5rem 0}
caption{text-align:left;color:var(--muted);padding-bottom:.4rem}
th,td{padding:.4rem .75rem .4rem 0;text-align:left;vertical-align:top;border-bottom:1px solid var(--rule)}
th{font-weight:600;color:var(--muted);font-size:.85rem}
th.num,td.num{text-align:right;white-space:nowrap}
td.wrap{white-space:normal;overflow-wrap:anywhere;word-break:break-all;max-width:20rem}
th[scope=row]{font-weight:600;color:var(--ink);font-size:1rem;white-space:nowrap}
.after{color:var(--seam);font-weight:600}
.down{color:var(--pass)}.up{color:var(--crit)}
.status{display:inline-block;padding:.1rem .6rem;border:2px solid currentColor;font-weight:700;letter-spacing:.04em;font-size:.85rem}
.status.pass{color:var(--pass)}.status.fail{color:var(--crit)}.status.skipped{color:var(--muted)}
.sev{display:inline-block;width:.7rem;height:.7rem;margin-right:.45rem;vertical-align:-.05rem;border:2px solid currentColor}
.sev-critical{color:var(--crit);background:currentColor}
.sev-high{color:var(--crit);background:linear-gradient(90deg,currentColor 50%,transparent 50%)}
.sev-medium{color:var(--warn)}
.sev-low{color:var(--muted);border-radius:50%;width:.5rem;height:.5rem;margin:0 .6rem 0 .1rem;background:currentColor}
.sev-unrated{color:var(--stone);border-style:dashed}
details{border-bottom:1px solid var(--rule)}
details>summary{cursor:pointer;list-style:none;padding:.5rem 0;touch-action:manipulation}
details>summary:hover{color:var(--seam)}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:"+";display:inline-block;width:1.2rem;color:var(--seam);font-weight:700}
details[open]>summary::before{content:"-"}
summary:focus-visible{outline:2px solid var(--seam);outline-offset:2px}
.rm>summary{display:grid;grid-template-columns:1.2rem 4.5rem minmax(0,1fr) 9rem 6.5rem;gap:.5rem;align-items:baseline}
.rm .num{text-align:right;white-space:nowrap}
.rm>summary::before{grid-column:1}
.rm .name{overflow-wrap:anywhere}
.rm .why{color:var(--muted)}
.ev{padding:0 0 .9rem 1.2rem;color:var(--muted)}
.ev ul{margin:.25rem 0 0;padding:0;list-style:none}
.ev li{padding:.15rem 0}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:.5rem 2rem}
dl{margin:.25rem 0}dt{color:var(--muted);font-size:.85rem}dd{margin:0 0 .5rem}
.keep{font-size:.9rem}
.note{margin:.5rem 0;max-width:68ch}
.note::before{content:"Note: ";font-weight:700;color:var(--seam)}
.note.differs::before{content:"Differs from the original: ";color:var(--crit)}
footer{margin-top:3rem;color:var(--muted);font-size:.85rem}
@media (max-width:40rem){.rm>summary{grid-template-columns:1.2rem minmax(0,1fr) 6.5rem}.rm .kind,.rm .why{display:none}}
@media print{
:root{--ground:#fff;--ink:#000;--stone:#666;--muted:#333;--seam:#1d4553;--crit:#000;--warn:#000;--pass:#000;--rule:#bbb}
body{font-size:11pt}main{max-width:none;padding:0}
details>*{display:block!important}details::details-content{content-visibility:visible!important;display:block!important}
details>summary::before{content:""}h2{break-after:avoid}tr,details{break-inside:avoid}
}
"#;

pub fn to_html(r: &Report) -> String {
    let mut o = String::with_capacity(32 * 1024);
    let _ = write!(
        o,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <meta name=\"color-scheme\" content=\"light dark\">\n\
         <meta name=\"theme-color\" content=\"#F3F1EC\" media=\"(prefers-color-scheme: light)\">\n\
         <meta name=\"theme-color\" content=\"#17191C\" media=\"(prefers-color-scheme: dark)\">\n\
         <title>Bedrock report: {}</title>\n<style>{}</style>\n</head>\n<body>\n<main>\n",
        esc(&r.input.reference),
        CSS
    );

    let _ = write!(
        o,
        "<header>\n<h1>Bedrock report</h1>\n<p class=\"meta\"><code>{}</code> for {}</p>\n\
         <p class=\"meta\">Generated {} by Bedrock {}. Report schema {}.</p>\n</header>\n",
        esc(&r.input.reference),
        esc(&r.input.platform),
        esc(&r.timestamp),
        esc(&r.tool_version),
        esc(&r.schema_version)
    );

    summary(&mut o, r);
    if let Some(v) = &r.verify {
        verify(&mut o, v);
    }
    if let Some(t) = &r.trace {
        let _ = write!(
            o,
            "<h2>Trace</h2>\n<div class=\"cols\">\n\
             <dl><dt>Workload</dt><dd>{} ({:.1} s)</dd></dl>\n\
             <dl><dt>Files reached</dt><dd class=\"mono\">{} of {}</dd></dl>\n\
             <dl><dt>Packages reached</dt><dd class=\"mono\">{} of {}</dd></dl>\n\
             <dl><dt>Reached only in part</dt><dd class=\"mono\">{}</dd></dl>\n</div>\n",
            esc(&t.workload_kind),
            t.duration_ms as f64 / 1000.0,
            t.reached_files,
            t.total_files,
            t.reached_packages,
            t.total_packages,
            t.partially_reached_packages.len()
        );
        if !t.partially_reached_packages.is_empty() {
            let names: Vec<String> = t
                .partially_reached_packages
                .iter()
                .take(60)
                .map(|n| format!("<code>{}</code>", esc(n)))
                .collect();
            let more = t.partially_reached_packages.len().saturating_sub(60);
            let _ = writeln!(
                o,
                "<p class=\"meta\">Partly reached packages are where file-level pruning carries the most risk: {}{}.</p>",
                names.join(", "),
                if more > 0 { format!(" and {more} more") } else { String::new() }
            );
        }
    }
    if !r.removals.is_empty() {
        removals(&mut o, r);
    }
    if !r.retained_unreached.is_empty() {
        let _ = write!(
            o,
            "<h2>Kept, but never touched</h2>\n<p>These stay in the image because of the keep-list, the mandatory list, or a dependency of a reached program. They are the first candidates for a stricter run.</p>\n<details><summary>{} items</summary>\n<table><thead><tr><th>Name</th><th>Why it stays</th></tr></thead><tbody>\n",
            r.retained_unreached.len()
        );
        for x in r.retained_unreached.iter().take(MAX_REMOVALS) {
            let _ = writeln!(
                o,
                "<tr><td><code>{}</code></td><td>{}</td></tr>",
                esc(&x.name),
                esc(&x.reason)
            );
        }
        o.push_str("</tbody></table>\n</details>\n");
    }
    if !r.findings.is_empty() {
        findings(&mut o, r);
    }
    if !r.notes.is_empty() {
        o.push_str("<h2>Notes</h2>\n");
        for n in &r.notes {
            let _ = writeln!(o, "<p class=\"note\">{}</p>", esc(n));
        }
    }
    let _ = write!(
        o,
        "<footer>Advisory snapshot <span class=\"digest\">{}</span>, updated {}. Finding counts change daily.</footer>\n</main>\n</body>\n</html>\n",
        esc(&r.snapshot.digest),
        esc(&r.snapshot.updated_at)
    );
    o
}

fn summary(o: &mut String, r: &Report) {
    let i = &r.input;
    let ic = &i.findings_by_severity;
    o.push_str("<h2>Summary</h2>\n<table>\n");
    let delta_cell = |n: i64| {
        let class = if n < 0 {
            "down"
        } else if n > 0 {
            "up"
        } else {
            ""
        };
        format!("<td class=\"num {class}\">{n:+}</td>")
    };
    match (&r.output, &r.delta) {
        (Some(out), Some(d)) => {
            let oc = &out.findings_by_severity;
            let f = &d.findings_by_severity;
            o.push_str("<caption>Before and after, row by row.</caption>\n<thead><tr><th scope=\"col\"></th><th scope=\"col\" class=\"num\">Before</th><th scope=\"col\" class=\"num after\">After</th><th scope=\"col\" class=\"num\">Change</th></tr></thead>\n<tbody>\n");
            let row = |o: &mut String, label: &str, a: String, b: String, d: String| {
                // Digests are 71 characters of content that must stay whole, so they wrap anywhere.
                let wrap = if a.contains("class=\"digest\"") { " wrap" } else { "" };
                let _ = writeln!(o, "<tr><th scope=\"row\">{label}</th><td class=\"num{wrap}\">{a}</td><td class=\"num after{wrap}\">{b}</td>{d}</tr>");
            };
            row(
                o,
                "Image digest",
                format!("<span class=\"digest\">{}</span>", esc(&i.digest)),
                format!("<span class=\"digest\">{}</span>", esc(&out.digest)),
                "<td></td>".into(),
            );
            row(
                o,
                "Size",
                mb(i.size_bytes),
                mb(out.size_bytes),
                format!(
                    "<td class=\"num {}\">{:+.1}%</td>",
                    if d.size_pct < 0.0 { "down" } else { "up" },
                    d.size_pct
                ),
            );
            row(o, "Layers", i.layers.to_string(), out.layers.to_string(), "<td></td>".into());
            row(
                o,
                "Packages",
                i.packages.to_string(),
                out.packages.to_string(),
                delta_cell(d.packages),
            );
            for (sevr, a, b, c) in [
                (Some(Severity::Critical), ic.critical, oc.critical, f.critical),
                (Some(Severity::High), ic.high, oc.high, f.high),
                (Some(Severity::Medium), ic.medium, oc.medium, f.medium),
                (Some(Severity::Low), ic.low, oc.low, f.low),
                (None, ic.unknown, oc.unknown, f.unknown),
            ] {
                row(o, &sev(sevr), a.to_string(), b.to_string(), delta_cell(c));
            }
            o.push_str("</tbody>\n");
        }
        _ => {
            o.push_str("<caption>The image as scanned.</caption>\n<tbody>\n");
            let _ = writeln!(o, "<tr><th scope=\"row\">Image digest</th><td><span class=\"digest\">{}</span></td></tr>", esc(&i.digest));
            let _ = writeln!(
                o,
                "<tr><th scope=\"row\">Size</th><td class=\"num\">{}</td></tr>",
                mb(i.size_bytes)
            );
            let _ = writeln!(
                o,
                "<tr><th scope=\"row\">Layers</th><td class=\"num\">{}</td></tr>",
                i.layers
            );
            let _ = writeln!(
                o,
                "<tr><th scope=\"row\">Packages</th><td class=\"num\">{}</td></tr>",
                i.packages
            );
            for (sevr, n) in [
                (Some(Severity::Critical), ic.critical),
                (Some(Severity::High), ic.high),
                (Some(Severity::Medium), ic.medium),
                (Some(Severity::Low), ic.low),
                (None, ic.unknown),
            ] {
                let _ = writeln!(
                    o,
                    "<tr><th scope=\"row\">{}</th><td class=\"num\">{n}</td></tr>",
                    sev(sevr)
                );
            }
            o.push_str("</tbody>\n");
        }
    }
    o.push_str("</table>\n");
}

fn verify(o: &mut String, v: &super::Verify) {
    let class = match v.status.as_str() {
        "pass" => "pass",
        "fail" => "fail",
        _ => "skipped",
    };
    let _ = write!(
        o,
        "<h2>Verification</h2>\n<p><span class=\"status {class}\">{}</span> The pruned image was run with the same workload as the original.</p>\n",
        esc(&v.status.to_uppercase())
    );
    for m in &v.mismatches {
        let _ = writeln!(o, "<p class=\"note differs\">{}</p>", esc(m));
    }
    if !v.missed_paths.is_empty() {
        o.push_str("<p>The pruned run needed these paths and could not find them. Add them to a keep-list:</p>\n<table><thead><tr><th>Path</th><th>Keep-list line</th></tr></thead><tbody>\n");
        for p in &v.missed_paths {
            let _ = writeln!(o, "<tr><td><code>{0}</code></td><td><code class=\"keep\">paths = [\"{0}\"]</code></td></tr>", esc(p));
        }
        o.push_str("</tbody></table>\n");
    }
    if !v.enoent_warnings.is_empty() {
        let _ = write!(
            o,
            "<details><summary>{} paths were looked up and not found</summary>\n<ul class=\"ev\">",
            v.enoent_warnings.len()
        );
        for p in v.enoent_warnings.iter().take(MAX_REMOVALS) {
            let _ = write!(o, "<li><code>{}</code></li>", esc(p));
        }
        o.push_str("</ul></details>\n");
    }
}

fn removals(o: &mut String, r: &Report) {
    let by_id: HashMap<&str, Vec<&Finding>> = r.findings.iter().fold(HashMap::new(), |mut m, f| {
        m.entry(f.id.as_str()).or_default().push(f);
        m
    });
    let mut rows: Vec<&Removal> = r.removals.iter().collect();
    rows.sort_by(|a, b| {
        b.findings_removed
            .len()
            .cmp(&a.findings_removed.len())
            .then(b.kind.cmp(&a.kind))
            .then(a.name.cmp(&b.name))
    });
    let _ = write!(
        o,
        "<h2>What was removed</h2>\n<p>{} items, most findings removed first. Open a row for the evidence.</p>\n",
        rows.len()
    );
    for x in rows.iter().take(MAX_REMOVALS) {
        let _ = write!(
            o,
            "<details class=\"rm\"><summary><span class=\"kind\">{}</span><code class=\"name\">{}</code><span class=\"why\">{}</span><span class=\"num mono\">{} findings</span></summary>\n<div class=\"ev\"><p>{}</p>",
            esc(&x.kind),
            esc(&x.name),
            esc(&x.reason),
            x.findings_removed.len(),
            esc(explain(&x.reason))
        );
        if !x.findings_removed.is_empty() {
            o.push_str("<ul>");
            for id in x.findings_removed.iter().take(100) {
                let s = by_id.get(id.as_str()).and_then(|f| f.first()).and_then(|f| f.severity);
                let _ = write!(o, "<li>{} <code>{}</code></li>", sev(s), esc(id));
            }
            o.push_str("</ul>");
        }
        o.push_str("</div></details>\n");
    }
    if rows.len() > MAX_REMOVALS {
        let _ = writeln!(
            o,
            "<p class=\"meta\">{} more rows are in the JSON report.</p>",
            rows.len() - MAX_REMOVALS
        );
    }
}

fn findings(o: &mut String, r: &Report) {
    let title = if r.output.is_some() { "Findings in the original image" } else { "Findings" };
    let _ = writeln!(o, "<h2>{title}</h2>");
    let open = if r.output.is_some() { "" } else { " open" };
    let _ = write!(
        o,
        "<details{open}><summary>{} findings</summary>\n<table><thead><tr><th>Severity</th><th>ID</th><th>Package</th><th>Version</th><th>Fixed in</th></tr></thead><tbody>\n",
        r.findings.len()
    );
    for f in r.findings.iter().take(MAX_FINDINGS) {
        let _ = writeln!(
            o,
            "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
            sev(f.severity),
            esc(&f.id),
            esc(&f.package.name),
            esc(&f.package.version),
            f.fixed_version.as_deref().map_or("none".into(), |v| format!("<code>{}</code>", esc(v)))
        );
    }
    o.push_str("</tbody></table>\n");
    if r.findings.len() > MAX_FINDINGS {
        let _ = writeln!(
            o,
            "<p class=\"meta\">{} more findings are in the JSON report.</p>",
            r.findings.len() - MAX_FINDINGS
        );
    }
    o.push_str("</details>\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ImageSummary, PackageRef, Report, SnapshotRef, Verify};

    fn base() -> Report {
        let input = ImageSummary {
            reference: "evil<script>alert(1)</script>:1".into(),
            digest: "sha256:aaa".into(),
            platform: "linux/amd64".into(),
            size_bytes: 10 << 20,
            layers: 2,
            packages: 3,
            findings_by_severity: Default::default(),
        };
        let finding = Finding {
            id: "CVE-2024-1".into(),
            aliases: vec![],
            severity: Some(Severity::High),
            cvss: None,
            package: PackageRef {
                name: "x\u{1b}[31m<b>".into(),
                version: "1".into(),
                purl: String::new(),
            },
            fixed_version: None,
            fixed_package: None,
        };
        Report::new(
            input,
            SnapshotRef { digest: "snap".into(), updated_at: "now".into() },
            vec![finding],
            vec!["a & b".into()],
        )
    }

    #[test]
    fn is_self_contained_and_escapes_everything_from_the_image() {
        let html = to_html(&base());
        assert!(html.starts_with("<!doctype html>"));
        assert!(!html.contains("<script"), "no scripts");
        assert!(!html.contains("http://") && !html.contains("https://"), "no external requests");
        assert!(!html.contains("alert(1)</script>"));
        assert!(html.contains("evil&lt;script&gt;"));
        assert!(
            html.contains("x\\u{1b}[31m&lt;b&gt;"),
            "control characters are shown, not interpreted"
        );
        assert!(html.contains("a &amp; b"));
        assert!(html.contains("sev-high"));
    }

    #[test]
    fn slim_report_shows_before_after_removals_and_verify_failures() {
        let mut r = base();
        let mut out = r.input.clone();
        out.size_bytes = 3 << 20;
        out.packages = 1;
        r.delta = Some(crate::report::Delta::between(&r.input, &out));
        r.output = Some(out);
        r.removals = vec![crate::report::Removal {
            kind: "package".into(),
            name: "libfoo".into(),
            reason: "no_file_reached".into(),
            findings_removed: vec!["CVE-2024-1".into()],
        }];
        r.verify = Some(Verify {
            status: "fail".into(),
            missed_paths: vec!["/app/<x>".into()],
            enoent_warnings: vec![],
            mismatches: vec!["status 500".into()],
        });
        let html = to_html(&r);
        assert!(html.contains("class=\"num after\""));
        assert!(html.contains("-70.0%"));
        assert!(html.contains("status fail"));
        assert!(html.contains("paths = [\"/app/&lt;x&gt;\"]"));
        assert!(
            html.contains("<details class=\"rm\">") && html.contains("No file of this package")
        );
    }
}
