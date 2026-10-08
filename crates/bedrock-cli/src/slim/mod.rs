//! `bedrock slim`: trace, compute the keep set, assemble a new image, then
//! verify it behaves like the original (BEDROCK_SPEC.md 5.6, 5.7).
pub mod assemble;
pub mod glob;
pub mod keep;
pub mod pkgdb;
pub mod verify;

use crate::fs::{FileInventory, SizeLimits};
use crate::image::{build_inventory, parse_all_packages};
use crate::oci::OciLayout;
use crate::report::{
    Delta, ImageSummary, Removal, Report, Retained, SeverityCounts, SnapshotRef, TraceSummary,
};
use crate::sbom::{read_file, Package};
use crate::trace::workload::{Readiness, Workload};
use crate::trace::{self, ImageRef, ReachSet, TraceRequest};
use crate::vuln::{matcher, VulnerabilityDb};
use anyhow::{bail, Context, Result};
use keep::{Granularity, KeepList};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct SlimRequest<'a> {
    pub image: ImageRef,
    pub inventory: &'a FileInventory,
    /// (digest, tar path) in image order.
    pub layers: Vec<(String, PathBuf)>,
    pub config_json: Vec<u8>,
    pub cmd_override: Option<Vec<String>>,
    pub packages: &'a [Package],
    pub workload: Workload,
    pub readiness: Readiness,
    pub ready_timeout: Duration,
    pub timeout: Duration,
    pub keep_list: KeepList,
    pub granularity: Granularity,
    pub preserve_layers: bool,
    pub mandatory: bool,
    pub allow_partial_trace: bool,
    pub verify: bool,
    /// Where the pruned OCI layout is written. Must not exist or be empty.
    pub output: PathBuf,
    pub db: Option<&'a VulnerabilityDb>,
    pub limits: SizeLimits,
}

pub struct SlimResult {
    pub report: Report,
    /// False when verification failed; nothing was written to `output`.
    pub passed: bool,
}

fn rel(p: &str) -> PathBuf {
    PathBuf::from(p.trim_start_matches('/'))
}

/// Why a trace should not be trusted to prune from, if it should not.
fn partial_reason(reach: &ReachSet) -> Option<String> {
    let w = &reach.workload;
    if w.timed_out {
        return Some("the run hit --timeout".into());
    }
    if !w.stopped_by_bedrock && w.entrypoint_code.is_some_and(|c| c != 0) {
        return Some(format!("the entrypoint exited with code {}", w.entrypoint_code.unwrap_or(0)));
    }
    if w.script_exit.is_some_and(|c| c != 0) {
        return Some(format!(
            "the workload script exited with code {}",
            w.script_exit.unwrap_or(0)
        ));
    }
    if let Some(h) = w.http.iter().find(|h| h.status.is_none_or(|s| s >= 500)) {
        return Some(format!("request {} {} got {:?}", h.method, h.url, h.status));
    }
    None
}

fn scan_counts(db: Option<&VulnerabilityDb>, packages: &[Package]) -> Option<matcher::ScanOutcome> {
    matcher::scan(packages, db?).ok()
}

pub fn run(req: SlimRequest<'_>) -> Result<SlimResult> {
    if req.output.exists() && std::fs::read_dir(&req.output).is_ok_and(|mut d| d.next().is_some()) {
        bail!("{} already exists and is not empty", req.output.display());
    }
    let (os, arch) = req.image.platform.split_once('/').context("platform must be os/arch")?;
    let (os, arch) = (os.to_string(), arch.to_string());

    // 1. Trace the original.
    let base_req = |inventory, layers, config_json, packages| TraceRequest {
        image: req.image.clone(),
        inventory,
        layers,
        config_json,
        cmd_override: req.cmd_override.clone(),
        packages,
        workload: req.workload.clone(),
        readiness: req.readiness.clone(),
        ready_timeout: req.ready_timeout,
        timeout: req.timeout,
    };
    let reach = trace::run(base_req(
        req.inventory,
        req.layers.clone(),
        req.config_json.clone(),
        req.packages,
    ))?;
    if let Some(e) = &reach.workload.error {
        bail!("{e}");
    }
    if !req.allow_partial_trace {
        if let Some(why) = partial_reason(&reach) {
            bail!("the trace looks incomplete ({why}); pruning from it could remove needed files. Fix the workload, or pass --allow-partial-trace");
        }
    }

    // 2. Keep set.
    let reached: BTreeSet<PathBuf> = reach.paths.iter().map(|p| rel(&p.path)).collect();
    let dynamic: BTreeSet<PathBuf> =
        reach.paths.iter().filter(|p| !p.dynamic.is_empty()).map(|p| rel(&p.path)).collect();
    let plan = keep::plan(&keep::PlanInput {
        inventory: req.inventory,
        packages: req.packages,
        reached: &reached,
        dynamic: &dynamic,
        keep_list: &req.keep_list,
        mandatory: req.mandatory,
        granularity: req.granularity,
    });

    // 3. Package databases lose the packages that were removed.
    let mut notes = Vec::new();
    let overrides = package_db_overrides(&req, &plan, &mut notes)?;

    // 4. Assemble into a staging directory next to the output.
    let parent =
        req.output.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new().prefix(".bedrock-slim-").tempdir_in(parent)?;
    let assembled = assemble::assemble(&assemble::AssembleInput {
        inventory: req.inventory,
        layers: &req.layers,
        keep: &plan.keep,
        overrides: &overrides,
        config_json: &req.config_json,
        preserve_layers: req.preserve_layers,
        out: staging.path(),
    })
    .context("failed to assemble the pruned image")?;

    // 5. Read the result back, as any consumer would.
    let layout = OciLayout::new(staging.path());
    let manifest = layout.resolve_manifest(&os, &arch).context("pruned image is not readable")?;
    let blob = |d: &str| layout.get_blob_path(d);
    let inventory2 = build_inventory(&manifest, &blob, req.limits)?;
    let resolver = |d: &str| -> Option<PathBuf> { blob(d).ok().filter(|p| p.exists()) };
    let packages2 = parse_all_packages(&inventory2, resolver);

    // 6. Verify under the same workload.
    let verify = if req.verify {
        let layers2: Vec<(String, PathBuf)> = manifest
            .layers
            .iter()
            .map(|l| Ok((l.digest.clone(), blob(&l.digest)?)))
            .collect::<Result<_>>()?;
        let config2 = std::fs::read(blob(&manifest.config.digest)?)?;
        let pruned = trace::run(base_req(&inventory2, layers2, config2, &packages2));
        match pruned {
            Ok(r2) => verify::compare(&reach, &r2),
            // The original started; if the pruned one cannot, that is a verification failure.
            Err(e) => crate::report::Verify {
                status: "fail".into(),
                missed_paths: vec![],
                enoent_warnings: vec![],
                mismatches: vec![format!("the pruned image failed to run: {e:#}")],
            },
        }
    } else {
        crate::report::Verify {
            status: "skipped".into(),
            missed_paths: vec![],
            enoent_warnings: vec![],
            mismatches: vec![],
        }
    };
    let passed = verify.status != "fail";

    // 7. Findings, before and after.
    let before = scan_counts(req.db, req.packages);
    let after = scan_counts(req.db, &packages2);
    if before.is_none() {
        notes.push("no usable advisory snapshot: finding counts are not computed (run `bedrock db update`)".into());
    }
    let findings = before.as_ref().map(|b| b.findings.clone()).unwrap_or_default();
    if let Some(b) = &before {
        notes.extend(b.notes.iter().cloned());
    }
    let snapshot = req
        .db
        .and_then(|d| d.manifest().ok().flatten())
        .map(|m| SnapshotRef { digest: m.digest, updated_at: m.updated_at })
        .unwrap_or(SnapshotRef { digest: "none".into(), updated_at: String::new() });

    let input_size: u64 =
        req.layers.iter().filter_map(|(_, p)| std::fs::metadata(p).ok()).map(|m| m.len()).sum();
    let input = ImageSummary {
        reference: req.image.reference.clone(),
        digest: req.image.digest.clone(),
        platform: req.image.platform.clone(),
        size_bytes: input_size,
        layers: req.layers.len(),
        packages: req.packages.len(),
        findings_by_severity: SeverityCounts::default(),
    };
    let output = ImageSummary {
        reference: req.output.display().to_string(),
        digest: assembled.config_digest.clone(),
        platform: req.image.platform.clone(),
        size_bytes: assembled.size_bytes,
        layers: assembled.layers,
        packages: packages2.len(),
        findings_by_severity: after
            .as_ref()
            .map(|a| SeverityCounts::of(&a.findings))
            .unwrap_or_default(),
    };

    let mut by_package: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    for f in &findings {
        by_package.entry(f.package.name.as_str()).or_default().insert(f.id.as_str());
    }
    let mut removals: Vec<Removal> = plan
        .removed_packages
        .iter()
        .map(|(name, reason)| Removal {
            kind: "package".into(),
            name: name.clone(),
            reason: (*reason).into(),
            findings_removed: by_package
                .get(name.as_str())
                .map(|s| s.iter().map(|x| x.to_string()).collect())
                .unwrap_or_default(),
        })
        .collect();
    removals.extend(plan.removed_files.iter().map(|(p, reason)| Removal {
        kind: "file".into(),
        name: format!("/{}", p.display()).replace('\\', "/"),
        reason: (*reason).into(),
        findings_removed: vec![],
    }));

    let mut report = Report::new(input, snapshot, findings, notes);
    report.delta = Some(Delta::between(&report.input, &output));
    report.output = Some(output);
    report.trace = Some(TraceSummary {
        workload_kind: reach.workload.kind.clone(),
        duration_ms: reach.workload.duration_ms,
        reached_files: reach.coverage.reached_files,
        total_files: reach.coverage.total_files,
        reached_packages: reach.coverage.reached_packages,
        total_packages: reach.coverage.total_packages,
        partially_reached_packages: reach.coverage.partially_reached_packages.clone(),
    });
    report.removals = removals;
    report.retained_unreached = plan
        .retained_unreached
        .iter()
        .map(|(n, r)| Retained { name: n.clone(), reason: (*r).into() })
        .collect();
    report.verify = Some(verify);

    if passed {
        // Same directory as the staging area, so this is an atomic rename.
        let _ = std::fs::remove_dir(&req.output);
        std::fs::rename(staging.keep(), &req.output).with_context(|| {
            format!("failed to move the pruned image to {}", req.output.display())
        })?;
    }
    Ok(SlimResult { report, passed })
}

/// Rewritten dpkg/apk databases for the packages being removed.
fn package_db_overrides(
    req: &SlimRequest<'_>,
    plan: &keep::Plan,
    notes: &mut Vec<String>,
) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    let mut count: HashMap<&str, usize> = HashMap::new();
    for (n, _) in &plan.removed_packages {
        *count.entry(n.as_str()).or_default() += 1;
    }
    // Only names whose every package entry is going (multi-arch installs can share a name).
    let removed_of = |prefix: &str| -> BTreeSet<&str> {
        count
            .iter()
            .filter(|(name, n)| {
                let mine: Vec<_> = req.packages.iter().filter(|p| p.name == **name).collect();
                mine.len() == **n && mine.iter().all(|p| p.purl.starts_with(prefix))
            })
            .map(|(n, _)| *n)
            .collect()
    };
    let resolver =
        |digest: &str| req.layers.iter().find(|(d, _)| d == digest).map(|(_, p)| p.clone());
    let mut out = BTreeMap::new();

    let deb = removed_of("pkg:deb/");
    if !deb.is_empty() {
        let path = "var/lib/dpkg/status";
        if let Some(text) = read_file(req.inventory, &resolver, path)? {
            out.insert(
                PathBuf::from(path),
                pkgdb::dpkg_status_without(&String::from_utf8_lossy(&text), &deb).into_bytes(),
            );
        }
    }
    let apk = removed_of("pkg:apk/");
    if !apk.is_empty() {
        for path in ["lib/apk/db/installed", "usr/lib/apk/db/installed"] {
            if let Some(text) = read_file(req.inventory, &resolver, path)? {
                out.insert(
                    PathBuf::from(path),
                    pkgdb::apk_installed_without(&String::from_utf8_lossy(&text), &apk)
                        .into_bytes(),
                );
            }
        }
    }
    if plan
        .removed_packages
        .iter()
        .any(|(n, _)| req.packages.iter().any(|p| p.name == *n && p.purl.starts_with("pkg:rpm/")))
    {
        notes.push("rpm packages were removed from disk but the rpm database was not rewritten: the pruned image's SBOM still lists them".into());
    }
    Ok(out)
}
