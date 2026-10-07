use anyhow::{Context, Result};
use bedrock::fs::{self, FileInventory};
use bedrock::oci::{Cache, ImageReference, Manifest, OciLayout, RegistryClient};
use bedrock::{sbom, vuln};
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
        /// Target platform as os/arch (e.g. linux/arm64)
        #[arg(long, default_value = "linux/amd64")]
        platform: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Emit an SBOM (dpkg, apk, npm, and PyPI packages found in the image)
    Sbom {
        image: String,
        #[arg(long, value_enum, default_value_t = SbomFormat::Spdx)]
        format: SbomFormat,
        #[arg(long, default_value = "linux/amd64")]
        platform: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Vulnerability database management
    Db {
        #[command(subcommand)]
        action: DbAction,
    },
    /// Scan an image for vulnerabilities (not yet implemented — see BEDROCK_SPEC.md Phase 2)
    Scan {
        image: String,
        #[arg(long)]
        fail_on: Option<String>,
        #[arg(long, default_value = "terminal")]
        format: String,
    },
    /// Trace an image's reachability (not yet implemented — see BEDROCK_SPEC.md Phase 3)
    Trace {
        image: String,
        #[arg(long)]
        workload: Option<String>,
        #[arg(long)]
        workload_http: Option<String>,
        #[arg(long)]
        workload_duration: Option<String>,
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

#[derive(Subcommand)]
enum DbAction {
    /// Fetch a fresh advisory snapshot (not yet implemented — see BEDROCK_SPEC.md Phase 2)
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
    match reference {
        ImageReference::Registry { registry, repository, reference } => {
            let mut client = RegistryClient::new(registry, repository);
            client.authenticate().context("registry authentication failed")?;
            let manifest = client
                .resolve_manifest(reference, os, arch)
                .context("failed to resolve manifest")?;

            for layer in &manifest.layers {
                if !cache.blob_exists(&layer.digest) {
                    let blob_path = cache.get_blob_path(&layer.digest)?;
                    client
                        .fetch_blob(&layer.digest, &blob_path)
                        .with_context(|| format!("failed to fetch blob {}", layer.digest))?;
                }
            }
            let cache = cache.clone();
            Ok((manifest, Box::new(move |digest: &str| cache.get_blob_path(digest))))
        }
        ImageReference::OciLayout(path) => {
            let layout = OciLayout::new(path);
            let manifest =
                layout.resolve_manifest(os, arch).context("failed to resolve manifest")?;
            Ok((manifest, Box::new(move |digest: &str| layout.get_blob_path(digest))))
        }
        ImageReference::DockerArchive(_) => not_implemented("Docker save-format archives"),
    }
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
            Err(e) => eprintln!("Warning: failed to parse {what}: {e:#}"),
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
        eprintln!("Error: {e:?}");
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
                            setuid_setgid.push(path.display().to_string());
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
                DbAction::Update => not_implemented("db update")?,
                DbAction::Status => {
                    if let Some(meta) = db.status().context("failed to check DB status")? {
                        println!(
                            "Database status: {} entries. Last update: {}",
                            meta.entries_count, meta.updated_at
                        );
                    } else {
                        println!("Database is empty. Run `bedrock db update`.");
                    }
                }
            }
        }
        Commands::Scan { .. } => not_implemented("scan")?,
        Commands::Trace { .. } => not_implemented("trace")?,
        Commands::Slim { .. } => not_implemented("slim")?,
        Commands::Attest { .. } => not_implemented("attest")?,
        Commands::Report { .. } => not_implemented("report")?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_size;

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
