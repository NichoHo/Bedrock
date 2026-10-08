//! The verify gate (BEDROCK_SPEC.md 5.7): the pruned image must behave like
//! the original under the same workload. Compared:
//!
//! - entrypoint exit status, or that a long-running service stayed up
//! - workload outcome: script exit code, HTTP status codes and body digests
//! - any `ENOENT` the pruned run hit that the original run did not. A file the
//!   application swallowed a failure on is still missing, so this is reported
//!   as a warning even when everything else matches.
use crate::report::Verify;
use crate::trace::ReachSet;
use std::collections::BTreeSet;

pub fn compare(base: &ReachSet, pruned: &ReachSet) -> Verify {
    let (b, p) = (&base.workload, &pruned.workload);
    let mut mismatches = Vec::new();

    if let Some(e) = &p.error {
        mismatches.push(e.clone());
    }
    let exit = |code: Option<i32>, sig: Option<i32>| match (code, sig) {
        (Some(c), _) => format!("exit code {c}"),
        (None, Some(s)) => format!("killed by signal {s}"),
        (None, None) => "unknown exit".to_string(),
    };
    match (b.stopped_by_bedrock, p.stopped_by_bedrock) {
        // Both ran until Bedrock ended them: the service stayed up.
        (true, true) => {}
        (false, false) => {
            if (b.entrypoint_code, b.entrypoint_signal) != (p.entrypoint_code, p.entrypoint_signal)
            {
                mismatches.push(format!(
                    "entrypoint ended with {} (original: {})",
                    exit(p.entrypoint_code, p.entrypoint_signal),
                    exit(b.entrypoint_code, b.entrypoint_signal)
                ));
            }
        }
        (true, false) => mismatches.push(format!(
            "entrypoint ended on its own with {}, but the original kept running",
            exit(p.entrypoint_code, p.entrypoint_signal)
        )),
        (false, true) => {
            mismatches.push("entrypoint kept running, but the original ended on its own".into())
        }
    }
    if b.script_exit != p.script_exit {
        mismatches.push(format!(
            "workload script exit {:?} (original: {:?})",
            p.script_exit, b.script_exit
        ));
    }
    if b.http.len() != p.http.len() {
        mismatches.push(format!(
            "{} HTTP requests answered (original: {})",
            p.http.len(),
            b.http.len()
        ));
    }
    for (i, (x, y)) in b.http.iter().zip(&p.http).enumerate() {
        if x.status != y.status {
            mismatches.push(format!(
                "request {} {}: status {:?} (original: {:?})",
                i + 1,
                x.url,
                y.status,
                x.status
            ));
        } else if x.body_sha256 != y.body_sha256 {
            mismatches.push(format!(
                "request {} {}: response body differs from the original",
                i + 1,
                x.url
            ));
        }
    }

    let before: BTreeSet<&str> = base.missing.iter().map(|m| m.path.as_str()).collect();
    let new_missing: Vec<String> = pruned
        .missing
        .iter()
        .filter(|m| !before.contains(m.path.as_str()))
        .map(|m| m.path.clone())
        .collect();

    if mismatches.is_empty() {
        Verify {
            status: "pass".into(),
            missed_paths: vec![],
            enoent_warnings: new_missing,
            mismatches,
        }
    } else {
        Verify {
            status: "fail".into(),
            missed_paths: new_missing,
            enoent_warnings: vec![],
            mismatches,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::workload::HttpResult;
    use crate::trace::{Coverage, ImageRef, MissingPath, WorkloadInfo};

    fn reach(w: WorkloadInfo, missing: &[&str]) -> ReachSet {
        ReachSet {
            schema_version: "1".into(),
            tool_version: "0".into(),
            timestamp: String::new(),
            image: ImageRef {
                reference: String::new(),
                digest: String::new(),
                platform: String::new(),
            },
            workload: w,
            paths: vec![],
            missing: missing
                .iter()
                .map(|p| MissingPath { path: p.to_string(), syscalls: vec!["openat".into()] })
                .collect(),
            coverage: Coverage::default(),
        }
    }

    fn service(status: u16, sha: &str) -> WorkloadInfo {
        WorkloadInfo {
            stopped_by_bedrock: true,
            http: vec![HttpResult {
                method: "GET".into(),
                url: "http://x/".into(),
                status: Some(status),
                body_sha256: Some(sha.into()),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn identical_runs_pass_and_new_enoent_is_a_warning() {
        let base = reach(service(200, "a"), &["/etc/optional.conf"]);
        let pruned = reach(service(200, "a"), &["/etc/optional.conf", "/usr/share/swallowed.dat"]);
        let v = compare(&base, &pruned);
        assert_eq!(v.status, "pass");
        assert_eq!(v.enoent_warnings, ["/usr/share/swallowed.dat"]);
        assert!(v.missed_paths.is_empty());
    }

    #[test]
    fn a_changed_response_fails_and_names_the_missing_paths() {
        let base = reach(service(200, "a"), &[]);
        let pruned = reach(service(500, "b"), &["/app/templates/index.html"]);
        let v = compare(&base, &pruned);
        assert_eq!(v.status, "fail");
        assert_eq!(v.missed_paths, ["/app/templates/index.html"]);
        assert!(v.mismatches[0].contains("status"), "{:?}", v.mismatches);

        let body_only = compare(&base, &reach(service(200, "b"), &[]));
        assert_eq!(body_only.status, "fail");
        assert!(body_only.mismatches[0].contains("body"));
    }

    #[test]
    fn exit_status_and_survival_are_compared() {
        let ended = |code| WorkloadInfo { entrypoint_code: Some(code), ..Default::default() };
        assert_eq!(compare(&reach(ended(0), &[]), &reach(ended(0), &[])).status, "pass");
        assert_eq!(compare(&reach(ended(0), &[]), &reach(ended(1), &[])).status, "fail");
        // The original kept serving; the pruned one crashed on its own.
        let crashed = WorkloadInfo { entrypoint_code: Some(1), ..Default::default() };
        assert_eq!(compare(&reach(service(200, "a"), &[]), &reach(crashed, &[])).status, "fail");
    }

    #[test]
    fn a_failed_pruned_run_fails_verification() {
        let mut w = service(200, "a");
        w.error = Some("the entrypoint was not ready within 30s".into());
        let v = compare(&reach(service(200, "a"), &[]), &reach(w, &["/app/main.py"]));
        assert_eq!(v.status, "fail");
        assert_eq!(v.missed_paths, ["/app/main.py"]);
    }
}
