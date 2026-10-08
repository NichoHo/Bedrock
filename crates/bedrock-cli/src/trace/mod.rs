//! Reachability trace (BEDROCK_SPEC.md 5.5): run the image's entrypoint under
//! ptrace with a workload, then union the dynamic observations with the static
//! ELF/shebang closure into a `ReachSet`.
pub mod closure;
pub mod config;
pub mod record;
pub mod resolve;
pub mod workload;

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub mod tracer;

use crate::fs::{EntryKind, FileInventory};
use crate::sbom::Package;
use record::Evidence;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use workload::HttpResult;

pub const SCHEMA_VERSION: &str = "1";

/// Errors `main` maps to exit code 4 (environment) rather than 1.
#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    #[error("tracing needs Linux on x86-64 or arm64 (ptrace); run it on a Linux host or in a Linux container")]
    Unsupported,
    #[error("sandbox could not start the entrypoint: {0}")]
    Sandbox(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachSet {
    pub schema_version: String,
    pub tool_version: String,
    pub timestamp: String,
    pub image: ImageRef,
    pub workload: WorkloadInfo,
    /// Paths that exist in the image and were reached, sorted.
    pub paths: Vec<ReachedPath>,
    /// Paths the entrypoint looked for and did not find.
    pub missing: Vec<MissingPath>,
    pub coverage: Coverage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRef {
    pub reference: String,
    pub digest: String,
    pub platform: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkloadInfo {
    pub kind: String,
    pub duration_ms: u64,
    /// Readiness signal seen (`None` when no readiness was requested).
    pub ready: Option<bool>,
    pub entrypoint_code: Option<i32>,
    pub entrypoint_signal: Option<i32>,
    /// The entrypoint was still running at the end and Bedrock stopped it.
    pub stopped_by_bedrock: bool,
    pub timed_out: bool,
    /// Script exit code (`None` if no script, or killed by a signal).
    pub script_exit: Option<i32>,
    pub http: Vec<HttpResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachedPath {
    /// Absolute path inside the image.
    pub path: String,
    /// `dynamic`, `static` or `both`.
    pub origin: String,
    /// Packages that own this path.
    pub packages: Vec<String>,
    pub dynamic: Vec<Evidence>,
    #[serde(rename = "static")]
    pub static_deps: Vec<StaticEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticEvidence {
    /// `PT_INTERP`, `DT_NEEDED` or `shebang`.
    pub via: String,
    pub needed_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingPath {
    pub path: String,
    pub syscalls: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub reached_files: usize,
    pub total_files: usize,
    pub reached_packages: usize,
    pub total_packages: usize,
    /// Packages with some, but not all, of their files reached: where
    /// file-level pruning carries the most risk.
    pub partially_reached_packages: Vec<String>,
}

/// Everything `run` needs, already resolved by the caller.
pub struct TraceRequest<'a> {
    pub image: ImageRef,
    pub inventory: &'a FileInventory,
    /// (digest, tar path) in image order.
    pub layers: Vec<(String, PathBuf)>,
    pub config_json: Vec<u8>,
    pub cmd_override: Option<Vec<String>>,
    pub packages: &'a [Package],
    pub workload: workload::Workload,
    pub readiness: workload::Readiness,
    pub ready_timeout: std::time::Duration,
    pub timeout: std::time::Duration,
}

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub fn run(_req: TraceRequest<'_>) -> anyhow::Result<ReachSet> {
    Err(TraceError::Unsupported.into())
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn run(req: TraceRequest<'_>) -> anyhow::Result<ReachSet> {
    use anyhow::{bail, Context};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use workload::Workload;

    let mut cfg = config::RunConfig::parse(&req.config_json, req.cmd_override.clone())?;
    let rootfs = tempfile::tempdir().context("failed to create the sandbox rootfs")?;
    req.inventory
        .materialize(rootfs.path(), &req.layers)
        .context("failed to extract the image filesystem")?;
    cfg.argv[0] = cfg.program(rootfs.path())?;
    let (uid, gid) = cfg.ids(rootfs.path())?;
    let ld_library_path: Vec<String> = cfg
        .env
        .iter()
        .find_map(|e| e.strip_prefix("LD_LIBRARY_PATH="))
        .map(|v| v.split(':').filter(|s| !s.is_empty()).map(String::from).collect())
        .unwrap_or_default();

    let spec = tracer::RunSpec {
        rootfs: rootfs.path().to_path_buf(),
        argv: cfg.argv.clone(),
        env: cfg.env.clone(),
        cwd: cfg.working_dir.clone(),
        uid,
        gid,
        timeout: req.timeout,
        log_pattern: req.readiness.log_pattern.clone(),
    };

    #[derive(Default)]
    struct Driven {
        ready: Option<bool>,
        script_exit: Option<i32>,
        http: Vec<HttpResult>,
        error: Option<String>,
    }

    let control = Arc::new(tracer::Control::default());
    let started = Instant::now();
    let workload_plan = req.workload.clone();
    let readiness = req.readiness.clone();
    let ready_timeout = req.ready_timeout;
    let driver = move |control: Arc<tracer::Control>| {
        std::thread::spawn(move || {
            let mut d = Driven::default();
            let finished = || control.finished.load(Ordering::SeqCst);
            match &workload_plan {
                Workload::Duration(dur) => {
                    let end = Instant::now() + *dur;
                    while Instant::now() < end && !finished() {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
                Workload::Script(_) | Workload::Http(_) => {
                    let end = Instant::now() + ready_timeout;
                    let mut ready = false;
                    while !ready && Instant::now() < end && !finished() {
                        ready = readiness.log_pattern.is_some()
                            && control.log_seen.load(Ordering::SeqCst)
                            || readiness.port.is_some_and(|p| {
                                workload::wait_for_port(p, Duration::from_millis(300), finished)
                            });
                        if !ready {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                    d.ready = Some(ready);
                    if ready {
                        match &workload_plan {
                            Workload::Script(path) => {
                                match workload::run_script(path, readiness.port) {
                                    Ok(code) => d.script_exit = code,
                                    Err(e) => d.error = Some(format!("{e:#}")),
                                }
                            }
                            Workload::Http(path) => {
                                let port = readiness.port.unwrap_or(0);
                                match std::fs::read_to_string(path)
                                    .map_err(anyhow::Error::from)
                                    .and_then(|t| workload::parse_http_file(&t))
                                {
                                    Ok(reqs) => d.http = workload::replay_http(&reqs, port),
                                    Err(e) => d.error = Some(format!("{e:#}")),
                                }
                            }
                            Workload::Duration(_) => {}
                        }
                    }
                }
            }
            // Workload done (or never became ready): let the entrypoint shut down.
            if !finished() {
                control.stop.store(1, Ordering::SeqCst);
            }
            d
        })
    };

    let (outcome, driven) = tracer::run(&spec, &control, driver).context("tracer failed")?;
    if let Some(msg) = &outcome.spawn_error {
        return Err(TraceError::Sandbox(msg.trim().to_string()).into());
    }
    if let Some(e) = driven.error {
        bail!("workload failed: {e}");
    }
    if driven.ready == Some(false) {
        bail!(
            "the entrypoint was not ready within {}s (check --ready-port / --ready-log-pattern)",
            req.ready_timeout.as_secs()
        );
    }

    let workload = WorkloadInfo {
        kind: req.workload.kind().into(),
        duration_ms: started.elapsed().as_millis() as u64,
        ready: driven.ready,
        entrypoint_code: outcome.exit.code,
        entrypoint_signal: outcome.exit.signal,
        stopped_by_bedrock: outcome.terminated_by_tracer,
        timed_out: outcome.timed_out,
        script_exit: driven.script_exit,
        http: driven.http,
    };
    Ok(assemble(
        req.image,
        workload,
        outcome.recorder,
        rootfs.path(),
        req.inventory,
        req.packages,
        &ld_library_path,
    ))
}

/// Combines dynamic observations with the static closure and measures coverage.
pub fn assemble(
    image: ImageRef,
    workload: WorkloadInfo,
    recorder: record::Recorder,
    rootfs: &Path,
    inventory: &FileInventory,
    packages: &[Package],
    ld_library_path: &[String],
) -> ReachSet {
    let rel = |p: &Path| PathBuf::from(p.strip_prefix("/").unwrap_or(p));
    // Only paths that are part of the image: the sandbox adds /proc, /dev/null, etc.
    let in_image = |p: &Path| inventory.files.contains_key(&rel(p));

    let mut entries: BTreeMap<PathBuf, ReachedPath> = BTreeMap::new();
    let mut seeds = Vec::new();
    for (path, evidence) in &recorder.reached {
        if !in_image(path) {
            continue;
        }
        if inventory
            .files
            .get(&rel(path))
            .is_some_and(|m| matches!(m.kind, EntryKind::File | EntryKind::HardLink(_)))
        {
            seeds.push(rel(path));
        }
        entries.insert(
            path.clone(),
            ReachedPath {
                path: path.display().to_string(),
                origin: "dynamic".into(),
                packages: vec![],
                dynamic: evidence.clone(),
                static_deps: vec![],
            },
        );
    }
    for (path, deps) in closure::closure(rootfs, &seeds, ld_library_path) {
        let abs = Path::new("/").join(&path);
        if !inventory.files.contains_key(&path) {
            continue;
        }
        let e = entries.entry(abs.clone()).or_insert_with(|| ReachedPath {
            path: abs.display().to_string(),
            origin: "static".into(),
            packages: vec![],
            dynamic: vec![],
            static_deps: vec![],
        });
        if !e.dynamic.is_empty() {
            e.origin = "both".into();
        }
        e.static_deps = deps
            .into_iter()
            .map(|d| StaticEvidence {
                via: d.via.into(),
                needed_by: Path::new("/").join(d.needed_by).display().to_string(),
            })
            .collect();
    }

    // path -> owning package names
    let mut owners: BTreeMap<&Path, Vec<&str>> = BTreeMap::new();
    for pkg in packages {
        for f in &pkg.files {
            owners.entry(f.as_path()).or_default().push(&pkg.name);
        }
    }
    let reached_rel: BTreeSet<PathBuf> = entries.keys().map(|p| rel(p)).collect();
    for (abs, e) in entries.iter_mut() {
        if let Some(o) = owners.get(rel(abs).as_path()) {
            e.packages = o.iter().map(|s| s.to_string()).collect();
        }
    }

    let is_file =
        |m: &crate::fs::FileMetadata| matches!(m.kind, EntryKind::File | EntryKind::HardLink(_));
    let total_files = inventory.files.values().filter(|m| is_file(m)).count();
    let reached_files =
        inventory.files.iter().filter(|(p, m)| is_file(m) && reached_rel.contains(*p)).count();
    let mut reached_packages = 0;
    let mut partial = Vec::new();
    for pkg in packages {
        let hit = pkg.files.iter().filter(|f| reached_rel.contains(*f)).count();
        if hit > 0 {
            reached_packages += 1;
            if hit < pkg.files.len() {
                partial.push(pkg.name.clone());
            }
        }
    }
    partial.sort();
    partial.dedup();

    ReachSet {
        schema_version: SCHEMA_VERSION.into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        image,
        workload,
        paths: entries.into_values().collect(),
        missing: recorder
            .missing
            .into_iter()
            .map(|(p, s)| MissingPath {
                path: p.display().to_string(),
                syscalls: s.into_iter().collect(),
            })
            .collect(),
        coverage: Coverage {
            reached_files,
            total_files,
            reached_packages,
            total_packages: packages.len(),
            partially_reached_packages: partial,
        },
    }
}
