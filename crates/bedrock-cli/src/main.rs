use anyhow::{Context, Result};
use bedrock::fs::{self, FileInventory};
use bedrock::oci::archive::DockerArchive;
use bedrock::oci::{Cache, ImageReference, Manifest, OciLayout, RegistryClient};
use bedrock::{escape_control, report, sbom, vuln};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "bedrock")]
#[command(about = "Bedrock - container size reduction tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect an image: layers, sizes, file count
    Inspect {
        /// Image reference (e.g. ubuntu:latest), OCI layout directory, or .tar archive
        image: String,
        /// Target platform as os/arch (e.g. linux/arm64). Defaults to this machine's architecture
        #[arg(long, default_value_t = default_platform())]
        platform: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Emit an SBOM (dpkg, apk, npm, and PyPI packages found in the image)
    Sbom {
        image: String,
        #[arg(long, value_enum, default_value_t = SbomFormat::Spdx)]
        format: SbomFormat,
        /// Target platform as os/arch (e.g. linux/arm64). Defaults to this machine's architecture
        #[arg(long, default_value_t = default_platform())]
        platform: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Vulnerability database management
    Db {
        #[command(subcommand)]
        action: DbAction,
    },
    /// Scan an image for known vulnerabilities, using the local advisory snapshot
    Scan {
        image: String,
        /// Exit 1 if any finding has at least this severity. Unrated findings never fail the gate
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
        #[arg(long, value_enum, default_value_t = ScanFormat::Terminal)]
        format: ScanFormat,
        /// Write the report to this file instead of stdout
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// Target platform as os/arch (e.g. linux/arm64). Defaults to this machine's architecture
        #[arg(long, default_value_t = default_platform())]
        platform: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Run an image's entrypoint under ptrace with a workload and report which files it reached
    Trace {
        image: String,
        #[command(flatten)]
        workload: WorkloadArgs,
        /// Write the reach set (JSON) to this file instead of stdout
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// Target platform as os/arch (e.g. linux/arm64). Defaults to this machine's architecture
        #[arg(long, default_value_t = default_platform())]
        platform: String,
        #[command(flatten)]
        limits: LimitArgs,
        /// Replace the image's Cmd (arguments after `--`)
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Prune and verify an image (not yet implemented — see BEDROCK_SPEC.md Phase 4)
    Slim {
        image: String,
        #[arg(long)]
        workload: Option<String>,
        #[arg(long)]
        workload_http: Option<String>,
        #[arg(long)]
        workload_duration: Option<String>,
        #[arg(long)]
        keep_list: Option<String>,
        #[arg(long)]
        preserve_layers: bool,
    },
    /// Sign and attest an image (not yet implemented — see BEDROCK_SPEC.md Phase 5)
    Attest {
        image: String,
        /// Key-based signing; omit for keyless (OIDC) signing, the CI default
        #[arg(long)]
        key: Option<String>,
    },
    /// Render a saved prune report (not yet implemented — see BEDROCK_SPEC.md Phase 6)
    Report {
        #[arg(long, default_value = "markdown")]
        format: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum SbomFormat {
    Spdx,
    Cyclonedx,
}

/// Decompression-bomb limits on uncompressed layer data.
#[derive(Args)]
struct LimitArgs {
    /// Max uncompressed size of one layer (e.g. 500M, 16G)
    #[arg(long, value_parser = parse_size, default_value = "16G")]
    max_layer_size: u64,
    /// Max uncompressed size of all layers combined (e.g. 64G)
    #[arg(long, value_parser = parse_size, default_value = "64G")]
    max_image_size: u64,
}

impl LimitArgs {
    fn limits(&self) -> fs::SizeLimits {
        fs::SizeLimits { per_layer: self.max_layer_size, per_image: self.max_image_size }
    }
}

/// Parses a byte count with an optional binary suffix: `1048576`, `512K`, `500M`, `16G`, `1T`.
fn parse_size(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    let (digits, shift) = match s.as_bytes().last().map(u8::to_ascii_uppercase) {
        Some(b'K') => (&s[..s.len() - 1], 10),
        Some(b'M') => (&s[..s.len() - 1], 20),
        Some(b'G') => (&s[..s.len() - 1], 30),
        Some(b'T') => (&s[..s.len() - 1], 40),
        _ => (s, 0),
    };
    let n: u64 =
        digits.parse().map_err(|_| format!("invalid size {s:?}, expected e.g. 500M or 16G"))?;
    n.checked_mul(1 << shift).ok_or_else(|| format!("size {s:?} is too large"))
}

/// How to exercise the entrypoint while it is traced. Exactly one workload is required.
#[derive(Args)]
struct WorkloadArgs {
    /// Script run on the host once the entrypoint is ready (needs --ready-port or --ready-log-pattern)
    #[arg(long)]
    workload: Option<PathBuf>,
    /// .http file of requests replayed against the container (needs --ready-port)
    #[arg(long)]
    workload_http: Option<PathBuf>,
    /// Run idle for this long, e.g. 30s. Captures startup only: the weakest option
    #[arg(long)]
    workload_duration: Option<String>,
    /// Port on 127.0.0.1 that accepts connections once the entrypoint is ready
    #[arg(long)]
    ready_port: Option<u16>,
    /// Text in the entrypoint's output that means it is ready (plain substring)
    #[arg(long)]
    ready_log_pattern: Option<String>,
    /// Give up waiting for readiness after this long
    #[arg(long, default_value = "30s")]
    ready_timeout: String,
    /// Stop the whole run after this long
    #[arg(long, default_value = "10m")]
    timeout: String,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Low,
    Medium,
    High,
    Critical,
}

impl From<FailOn> for vuln::Severity {
    fn from(f: FailOn) -> Self {
        match f {
            FailOn::Low => Self::Low,
            FailOn::Medium => Self::Medium,
            FailOn::High => Self::High,
            FailOn::Critical => Self::Critical,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum ScanFormat {
    Terminal,
    Json,
    Sarif,
}

/// An error that maps to a documented exit code (BEDROCK_SPEC.md 7.4).
#[derive(Debug)]
struct EnvironmentError(String);

impl std::fmt::Display for EnvironmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for EnvironmentError {}

#[derive(Subcommand)]
enum DbAction {
    /// Fetch a fresh advisory snapshot (OSV, Debian, Alpine, Red Hat). Uses the network.
    Update,
    /// Report on the currently cached advisory snapshot, if any
    Status,
}

/// Marks a command whose interface exists (it parses, and matches the design
/// in BEDROCK_SPEC.md) but whose implementation doesn't exist yet. Identified
/// by type rather than by matching an error string, so it survives any
/// `.context()` wrapping applied between where it's raised and `main`.
#[derive(Debug)]
struct NotImplemented(&'static str);

impl std::fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}` is not implemented yet (see BEDROCK_SPEC.md for the roadmap)", self.0)
    }
}
impl std::error::Error for NotImplemented {}

fn not_implemented<T>(what: &'static str) -> Result<T> {
    Err(NotImplemented(what).into())
}

/// Resolves a blob digest to its local path on disk.
type BlobPathFn = Box<dyn Fn(&str) -> Result<PathBuf>>;

/// The host's architecture with the `linux` OS: container images are Linux
/// images even when Bedrock runs on macOS or Windows. Architecture names are
/// Go's (what registries use), not Rust's.
fn default_platform() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "powerpc64" if cfg!(target_endian = "little") => "ppc64le",
        "powerpc64" => "ppc64",
        other => other,
    };
    format!("linux/{arch}")
}

fn parse_platform(platform: &str) -> Result<(String, String)> {
    let (os, arch) = platform
        .split_once('/')
        .with_context(|| format!("invalid --platform {platform:?}, expected e.g. linux/amd64"))?;
    Ok((os.to_string(), arch.to_string()))
}

/// Resolves an [`ImageReference`] down to a [`Manifest`] for the requested
/// platform, plus a way to get the local path of any of its blobs (already
/// downloaded and digest-verified, for a registry reference). This is the one
/// place that knows how to turn "an image, named some way" into "bytes on
/// disk", so `inspect` and `sbom` share it instead of each re-deriving it
/// (which is how the registry path silently diverged from the local-layout
/// path last time: only one of them followed manifest indexes).
fn resolve_image(
    reference: &ImageReference,
    cache: &Cache,
    os: &str,
    arch: &str,
) -> Result<(Manifest, BlobPathFn)> {
    let (manifest, blob_path): (Manifest, BlobPathFn) = match reference {
        ImageReference::Registry { registry, repository, reference } => {
            let mut client = RegistryClient::new(registry, repository);
            client.authenticate().context("registry authentication failed")?;
            let manifest = client
                .resolve_manifest(reference, os, arch)
                .context("failed to resolve manifest")?;

            for blob in std::iter::once(&manifest.config).chain(&manifest.layers) {
                if !cache.blob_exists(&blob.digest) {
                    let blob_path = cache.get_blob_path(&blob.digest)?;
                    client
                        .fetch_blob(&blob.digest, &blob_path)
                        .with_context(|| format!("failed to fetch blob {}", blob.digest))?;
                }
            }
            let cache = cache.clone();
            (manifest, Box::new(move |digest: &str| cache.get_blob_path(digest)))
        }
        ImageReference::OciLayout(path) => {
            let layout = OciLayout::new(path);
            let manifest =
                layout.resolve_manifest(os, arch).context("failed to resolve manifest")?;
            (manifest, Box::new(move |digest: &str| layout.get_blob_path(digest)))
        }
        ImageReference::DockerArchive(path) => {
            let (manifest, archive) = DockerArchive::open(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            // `archive` moves into the closure: dropping it deletes the unpacked layers.
            (manifest, Box::new(move |digest: &str| archive.blob_path(digest)))
        }
    };
    check_platform(&manifest, &*blob_path, os, arch)?;
    Ok((manifest, blob_path))
}

/// Config fields that say what platform an image was built for.
#[derive(serde::Deserialize)]
struct ImageConfigPlatform {
    os: Option<String>,
    architecture: Option<String>,
}

/// Rejects an image whose config says it is for a different platform than
/// requested. An index lookup already guarantees this, but a reference that
/// points straight at a single-platform manifest (or a layout or archive
/// holding one) gets no such check, and would otherwise be analysed as the
/// wrong architecture without a word. A config that doesn't say is accepted.
fn check_platform(
    manifest: &Manifest,
    blob_path: &dyn Fn(&str) -> Result<PathBuf>,
    os: &str,
    arch: &str,
) -> Result<()> {
    use std::io::Read;
    let path = blob_path(&manifest.config.digest)?;
    let mut data = Vec::new();
    // A config is a few KB; the cap stops a hostile one being buffered whole.
    std::fs::File::open(&path)
        .and_then(|f| f.take(16 << 20).read_to_end(&mut data))
        .with_context(|| format!("failed to read image config {}", path.display()))?;
    let cfg: ImageConfigPlatform =
        serde_json::from_slice(&data).context("image config is not valid JSON")?;
    for (what, want, got) in [("os", os, &cfg.os), ("architecture", arch, &cfg.architecture)] {
        if let Some(got) = got.as_deref().filter(|g| *g != want) {
            anyhow::bail!(
                "image is built for {what} {:?}, but {what} {want:?} was requested (see --platform)",
                escape_control(got)
            );
        }
    }
    Ok(())
}

fn build_inventory(
    manifest: &Manifest,
    blob_path: &dyn Fn(&str) -> Result<PathBuf>,
    limits: fs::SizeLimits,
) -> Result<FileInventory> {
    let mut inventory = FileInventory::with_limits(limits);
    for layer in &manifest.layers {
        let path = blob_path(&layer.digest)?;
        inventory
            .apply_layer(&path, &layer.digest)
            .with_context(|| format!("failed to apply layer {}", layer.digest))?;
    }
    Ok(inventory)
}

/// Runs every SBOM parser we have over `inventory`, collecting whatever each
/// one finds. A parser failing (a malformed dpkg status file, say) is
/// reported on stderr and doesn't stop the others from running, but it is
/// always reported — never silently dropped.
fn parse_all_packages(
    inventory: &FileInventory,
    resolver: impl Fn(&str) -> Option<PathBuf> + Copy,
) -> Vec<sbom::Package> {
    type Parser<F> = fn(&FileInventory, F) -> Result<Vec<sbom::Package>>;
    let parsers: [(&str, Parser<_>); 5] = [
        ("dpkg database", sbom::dpkg::parse_dpkg),
        ("apk database", sbom::apk::parse_apk),
        ("rpm database", sbom::rpm::parse_rpm),
        ("node_modules", sbom::node::parse_node),
        ("Python packages", sbom::python::parse_python),
    ];
    let mut packages = Vec::new();
    for (what, parse) in parsers {
        match parse(inventory, resolver) {
            Ok(found) => packages.extend(found),
            // {:#} prints the whole context chain on one line.
            Err(e) => {
                eprintln!("Warning: failed to parse {what}: {}", escape_control(&format!("{e:#}")))
            }
        }
    }
    packages
}

fn main() {
    if let Err(e) = run() {
        if let Some(ni) = e.downcast_ref::<NotImplemented>() {
            eprintln!("Error: {ni}");
            std::process::exit(4);
        }
        if e.downcast_ref::<EnvironmentError>().is_some()
            || e.downcast_ref::<bedrock::trace::TraceError>().is_some()
        {
            eprintln!("Error: {}", escape_control(&format!("{e:#}")));
            std::process::exit(4);
        }
        // Single-line chain, escaped: error text can quote paths from the image.
        eprintln!("Error: {}", escape_control(&format!("{e:#}")));
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Inspect { image, platform, limits } => {
            let (os, arch) = parse_platform(platform)?;
            let cache = Cache::new().context("failed to initialize cache")?;
            let reference = ImageReference::parse(image)?;

            println!("Image: {image}");
            let (manifest, blob_path) = resolve_image(&reference, &cache, &os, &arch)?;

            println!("Layers:");
            for (i, layer) in manifest.layers.iter().enumerate() {
                let size_mb = layer.size as f64 / 1_048_576.0;
                println!("  Layer {}: {} ({:.2} MB)", i, layer.digest, size_mb);
            }
            let inventory = build_inventory(&manifest, &*blob_path, limits.limits())?;

            let (mut files, mut dirs, mut symlinks, mut other) = (0u64, 0u64, 0u64, 0u64);
            let mut total_bytes = 0u64;
            let mut setuid_setgid = Vec::new();
            const S_ISUID: u32 = 0o4000;
            const S_ISGID: u32 = 0o2000;
            for (path, meta) in &inventory.files {
                match &meta.kind {
                    fs::EntryKind::File => {
                        files += 1;
                        total_bytes += meta.size;
                        if meta.mode & (S_ISUID | S_ISGID) != 0 {
                            setuid_setgid.push(escape_control(&path.display().to_string()));
                        }
                    }
                    fs::EntryKind::Directory => dirs += 1,
                    fs::EntryKind::Symlink(_) | fs::EntryKind::HardLink(_) => symlinks += 1,
                    fs::EntryKind::Other => other += 1,
                }
            }
            println!("Inventory:");
            println!("  Total entries: {}", inventory.files.len());
            println!(
                "  Files: {files} ({:.2} MB)   Directories: {dirs}   Symlinks/hardlinks: {symlinks}{}",
                total_bytes as f64 / 1_048_576.0,
                if other > 0 { format!("   Other: {other}") } else { String::new() }
            );
            if !setuid_setgid.is_empty() {
                setuid_setgid.sort();
                println!(
                    "  setuid/setgid binaries ({}): {}",
                    setuid_setgid.len(),
                    setuid_setgid.join(", ")
                );
            }
        }
        Commands::Sbom { image, format, platform, limits } => {
            let (os, arch) = parse_platform(platform)?;
            let cache = Cache::new().context("failed to initialize cache")?;
            let reference = ImageReference::parse(image)?;

            let (manifest, blob_path) = resolve_image(&reference, &cache, &os, &arch)?;
            let inventory = build_inventory(&manifest, &*blob_path, limits.limits())?;

            let resolver = |digest: &str| -> Option<PathBuf> {
                let p = blob_path(digest).ok()?;
                p.exists().then_some(p)
            };
            let packages = parse_all_packages(&inventory, resolver);
            let sbom = sbom::Sbom::new(packages, &inventory);

            match format {
                SbomFormat::Spdx => println!("{}", sbom::spdx::write_spdx(&sbom)),
                SbomFormat::Cyclonedx => println!("{}", sbom::cyclonedx::write_cyclonedx(&sbom)),
            }
        }
        Commands::Db { action } => {
            let db = vuln::VulnerabilityDb::new().context("failed to init vulnerability db")?;
            match action {
                DbAction::Update => {
                    let m = vuln::feeds::update(&db).context("db update failed")?;
                    println!(
                        "Snapshot {}: {} advisories from {} sources",
                        &m.digest[..12],
                        m.advisories(),
                        m.files.len()
                    );
                }
                DbAction::Status => {
                    if let Some(m) = db.manifest().context("failed to read snapshot manifest")? {
                        println!(
                            "Snapshot {} ({} advisories), updated {}",
                            &m.digest[..12],
                            m.advisories(),
                            m.updated_at
                        );
                        for f in &m.files {
                            println!("  {:<16} {:>8}", f.source, f.advisories);
                        }
                        if m.age_days().is_some_and(|d| d > 7) {
                            eprintln!(
                                "warning: snapshot is over 7 days old; run `bedrock db update`"
                            );
                        }
                    } else {
                        println!("Database is empty. Run `bedrock db update`.");
                    }
                }
            }
        }
        Commands::Scan { image, fail_on, format, output, platform, limits } => {
            let (os, arch) = parse_platform(platform)?;
            let cache = Cache::new().context("failed to initialize cache")?;
            let reference = ImageReference::parse(image)?;
            let (manifest, blob_path) = resolve_image(&reference, &cache, &os, &arch)?;
            let inventory = build_inventory(&manifest, &*blob_path, limits.limits())?;
            let resolver = |digest: &str| -> Option<PathBuf> {
                let p = blob_path(digest).ok()?;
                p.exists().then_some(p)
            };
            let packages = parse_all_packages(&inventory, resolver);

            // A missing or damaged snapshot is an environment problem (exit 4):
            // never scan against half a database.
            let db = vuln::VulnerabilityDb::new().context("failed to init vulnerability db")?;
            let snapshot =
                db.manifest().map_err(|e| EnvironmentError(format!("{e:#}")))?.ok_or_else(
                    || EnvironmentError("no advisory snapshot; run `bedrock db update`".into()),
                )?;
            if snapshot.age_days().is_some_and(|d| d > 7) {
                eprintln!("warning: advisory snapshot is over 7 days old; run `bedrock db update`");
            }
            let outcome = vuln::matcher::scan(&packages, &db)
                .map_err(|e| EnvironmentError(format!("{e:#}")))?;

            let summary = report::ImageSummary {
                reference: image.clone(),
                digest: manifest.config.digest.clone(),
                platform: platform.clone(),
                size_bytes: manifest.layers.iter().map(|l| l.size).sum(),
                layers: manifest.layers.len(),
                packages: packages.len(),
                findings_by_severity: Default::default(),
            };
            let snapshot_ref = report::SnapshotRef {
                digest: snapshot.digest.clone(),
                updated_at: snapshot.updated_at.clone(),
            };
            let report =
                report::Report::new(summary, snapshot_ref, outcome.findings, outcome.notes);

            let rendered = match format {
                ScanFormat::Terminal => report.to_terminal(),
                ScanFormat::Json => report.to_json(),
                ScanFormat::Sarif => report::sarif::to_sarif(&report),
            };
            match output {
                Some(path) => std::fs::write(
                    path,
                    rendered
                        + "
",
                )
                .with_context(|| format!("failed to write {}", path.display()))?,
                None => println!("{rendered}"),
            }

            if let Some(threshold) = fail_on {
                let threshold: vuln::Severity = (*threshold).into();
                let n = report.count_at_least(threshold);
                if n > 0 {
                    eprintln!("{n} finding(s) at or above {}", threshold.as_str());
                    std::process::exit(1);
                }
            }
        }
        Commands::Trace { image, workload: w, output, platform, limits, cmd } => {
            use bedrock::trace::workload::{parse_duration, Readiness, Workload};
            let usage = |msg: &str| -> ! {
                eprintln!("Error: {msg}");
                std::process::exit(3)
            };
            let chosen =
                [w.workload.is_some(), w.workload_http.is_some(), w.workload_duration.is_some()];
            if chosen.iter().filter(|c| **c).count() != 1 {
                usage("give exactly one of --workload, --workload-http, --workload-duration");
            }
            let workload = match (&w.workload, &w.workload_http, &w.workload_duration) {
                (Some(p), _, _) => Workload::Script(p.clone()),
                (_, Some(p), _) => Workload::Http(p.clone()),
                (_, _, Some(d)) => Workload::Duration(parse_duration(d)?),
                _ => unreachable!("checked above"),
            };
            if matches!(workload, Workload::Script(_))
                && w.ready_port.is_none()
                && w.ready_log_pattern.is_none()
            {
                usage("--workload needs --ready-port or --ready-log-pattern, so it knows when to start");
            }
            if matches!(workload, Workload::Http(_)) && w.ready_port.is_none() {
                usage("--workload-http needs --ready-port, the port the requests are sent to");
            }

            let (os, arch) = parse_platform(platform)?;
            let cache = Cache::new().context("failed to initialize cache")?;
            let reference = ImageReference::parse(image)?;
            let (manifest, blob_path) = resolve_image(&reference, &cache, &os, &arch)?;
            let inventory = build_inventory(&manifest, &*blob_path, limits.limits())?;
            let resolver = |digest: &str| -> Option<PathBuf> {
                let p = blob_path(digest).ok()?;
                p.exists().then_some(p)
            };
            let packages = parse_all_packages(&inventory, resolver);
            let layers = manifest
                .layers
                .iter()
                .map(|l| Ok((l.digest.clone(), blob_path(&l.digest)?)))
                .collect::<Result<Vec<_>>>()?;
            let config_json = std::fs::read(blob_path(&manifest.config.digest)?)
                .context("failed to read the image config")?;

            let reach = bedrock::trace::run(bedrock::trace::TraceRequest {
                image: bedrock::trace::ImageRef {
                    reference: image.clone(),
                    digest: manifest.config.digest.clone(),
                    platform: platform.clone(),
                },
                inventory: &inventory,
                layers,
                config_json,
                cmd_override: (!cmd.is_empty()).then(|| cmd.clone()),
                packages: &packages,
                workload,
                readiness: Readiness {
                    port: w.ready_port,
                    log_pattern: w.ready_log_pattern.clone(),
                },
                ready_timeout: parse_duration(&w.ready_timeout)?,
                timeout: parse_duration(&w.timeout)?,
            })?;
            let json = serde_json::to_string_pretty(&reach)?;
            match output {
                Some(path) => std::fs::write(
                    path,
                    json + "
",
                )
                .with_context(|| format!("failed to write {}", path.display()))?,
                None => println!("{json}"),
            }
            let c = &reach.coverage;
            eprintln!(
                "reached {}/{} files, {}/{} packages ({} partially)",
                c.reached_files,
                c.total_files,
                c.reached_packages,
                c.total_packages,
                c.partially_reached_packages.len()
            );
        }
        Commands::Slim { .. } => not_implemented("slim")?,
        Commands::Attest { .. } => not_implemented("attest")?,
        Commands::Report { .. } => not_implemented("report")?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{escape_control, parse_size};

    #[test]
    fn escape_control_neutralises_terminal_sequences() {
        let hostile = "bin/\x1b[2Jevil\nforged: line";
        let safe = escape_control(hostile);
        assert!(!safe.chars().any(char::is_control));
        assert_eq!(safe, "bin/\\u{1b}[2Jevil\\nforged: line");
        assert_eq!(escape_control("usr/bin/ünï"), "usr/bin/ünï");
    }

    #[test]
    fn parse_size_handles_suffixes_and_rejects_junk() {
        assert_eq!(parse_size("1024"), Ok(1024));
        assert_eq!(parse_size("512k"), Ok(512 << 10));
        assert_eq!(parse_size("16G"), Ok(16 << 30));
        assert!(parse_size("G").is_err());
        assert!(parse_size("1.5G").is_err());
        assert!(parse_size("99999999999T").is_err());
    }
}
