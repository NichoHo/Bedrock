use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use bedrock_oci::{Cache, ImageReference, RegistryClient};
use bedrock_fs::FileInventory;

#[derive(Parser)]
#[command(name = "bedrock")]
#[command(about = "Bedrock - container size reduction tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect an image
    Inspect {
        /// Image reference (e.g. ubuntu:latest)
        image: String,
    },
    /// Emit SBOM
    Sbom {
        /// Image reference (e.g. ubuntu:latest)
        image: String,
        /// Format: spdx or cyclonedx (default: spdx)
        #[arg(long, default_value = "spdx")]
        format: String,
    },
    /// Vulnerability database management
    Db {
        #[command(subcommand)]
        action: DbAction,
    },
    /// Scan an image for vulnerabilities
    Scan {
        /// Image reference
        image: String,
        /// Fail on severity (low, medium, high, critical)
        #[arg(long)]
        fail_on: Option<String>,
        /// Output format (default: terminal, options: sarif)
        #[arg(long, default_value = "terminal")]
        format: String,
    },
    /// Trace an image's reachability
    Trace {
        /// Image reference
        image: String,
        /// Workload script
        #[arg(long)]
        workload: Option<String>,
        /// Workload HTTP file
        #[arg(long)]
        workload_http: Option<String>,
        /// Workload duration (e.g. 30s)
        #[arg(long)]
        workload_duration: Option<String>,
    },
    /// Prune and verify an image
    Slim {
        /// Image reference
        image: String,
        /// Workload script
        #[arg(long)]
        workload: Option<String>,
        /// Workload HTTP file
        #[arg(long)]
        workload_http: Option<String>,
        /// Workload duration (e.g. 30s)
        #[arg(long)]
        workload_duration: Option<String>,
        /// Keep list TOML file
        #[arg(long)]
        keep_list: Option<String>,
        /// Preserve layers instead of squashing
        #[arg(long)]
        preserve_layers: bool,
    },
    /// Attest a pruned image
    Attest {
        /// Image reference
        image: String,
        /// Keyless signing
        #[arg(long, default_value = "true")]
        keyless: bool,
    },
    /// Generate a prune report
    Report {
        /// Format (markdown, html)
        #[arg(long, default_value = "markdown")]
        format: String,
    }
}

#[derive(Subcommand)]
enum DbAction {
    Update,
    Status,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        if e.to_string() == "not implemented" {
            eprintln!("Error: not implemented");
            std::process::exit(4);
        } else {
            eprintln!("Error: {:?}", e);
            std::process::exit(1);
        }
    }
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Inspect { image } => {
            let cache = Cache::new().await.context("Failed to initialize cache")?;
            
            let reference = ImageReference::parse(image);
            match reference {
                ImageReference::Registry { registry, repository, tag } => {
                    println!("Image: {}/{}", registry, repository);
                    println!("Tag: {}", tag);
                    
                    let mut client = RegistryClient::new(&registry, &repository);
                    client.authenticate().await.context("Authentication failed")?;
                    
                    println!("Fetching manifest...");
                    let manifest = client.fetch_manifest(&tag).await.context("Failed to fetch manifest")?;
                    
                    println!("Layers:");
                    let mut inventory = FileInventory::new();
                    
                    for (i, layer) in manifest.layers.iter().enumerate() {
                        let size_mb = layer.size as f64 / 1_048_576.0;
                        println!("  Layer {}: {} ({:.2} MB)", i, layer.digest, size_mb);
                        
                        if !cache.blob_exists(&layer.digest).await {
                            println!("    Downloading blob...");
                            let data = client.fetch_blob(&layer.digest).await.context("Failed to fetch blob")?;
                            cache.write_blob(&layer.digest, &data).await.context("Failed to write blob")?;
                        }
                        
                        let blob_path = cache.get_blob_path(&layer.digest);
                        inventory.apply_layer(&blob_path, &layer.digest).context("Failed to apply layer to inventory")?;
                    }
                    
                    println!("Inventory:");
                    println!("  Total files: {}", inventory.files.len());
                },
                ImageReference::OciLayout(path) => {
                    println!("OCI Layout: {}", path.display());
                    let layout = bedrock_oci::OciLayout::new(&path);
                    
                    if let Ok(manifests) = layout.read_index().await {
                        if let Some(desc) = manifests.first() {
                            println!("Using manifest digest: {}", desc.digest);
                            match layout.read_manifest(&desc.digest).await {
                                Ok(manifest) => {
                                    let mut inventory = FileInventory::new();
                                    for (i, layer) in manifest.layers.iter().enumerate() {
                                        let size_mb = layer.size as f64 / 1_048_576.0;
                                        println!("  Layer {}: {} ({:.2} MB)", i, layer.digest, size_mb);
                                        let blob_path = layout.get_blob_path(&layer.digest);
                                        if blob_path.exists() {
                                            inventory.apply_layer(&blob_path, &layer.digest).unwrap_or_else(|e| {
                                                println!("    (Failed to apply layer: {})", e);
                                            });
                                        } else {
                                            println!("    (Blob not found: {})", blob_path.display());
                                        }
                                    }
                                    println!("Inventory:");
                                    println!("  Total files: {}", inventory.files.len());
                                }
                                Err(e) => {
                                    println!("Failed to read manifest {}: {}", desc.digest, e);
                                }
                            }
                        } else {
                            println!("No manifests found in index.json");
                        }
                    } else {
                        println!("Failed to read index.json");
                    }
                },
                ImageReference::DockerArchive(_path) => {
                    anyhow::bail!("not implemented");
                }
            }
        },
        Commands::Sbom { image, format } => {
            let cache = Cache::new().await.context("Failed to initialize cache")?;
            let reference = ImageReference::parse(image);
            
            // Helper function to build inventory and get resolver
            // For now, only OciLayout is implemented fully for SBOM since fixtures use it.
            let mut inventory = FileInventory::new();
            
            match reference {
                ImageReference::OciLayout(path) => {
                    let layout = bedrock_oci::OciLayout::new(&path);
                    if let Ok(manifests) = layout.read_index().await {
                        if let Some(desc) = manifests.first() {
                            if let Ok(manifest) = layout.read_manifest(&desc.digest).await {
                                for layer in manifest.layers {
                                    let blob_path = layout.get_blob_path(&layer.digest);
                                    if blob_path.exists() {
                                        let _ = inventory.apply_layer(&blob_path, &layer.digest);
                                    }
                                }
                                
                                let resolver = |digest: &str| -> Option<std::path::PathBuf> {
                                    let bp = layout.get_blob_path(digest);
                                    if bp.exists() { Some(bp) } else { None }
                                };
                                
                                let mut packages = Vec::new();
                                packages.extend(bedrock_sbom::dpkg::parse_dpkg(&inventory, &resolver).unwrap_or_default());
                                packages.extend(bedrock_sbom::apk::parse_apk(&inventory, &resolver).unwrap_or_default());
                                packages.extend(bedrock_sbom::node::parse_node(&inventory).unwrap_or_default());
                                packages.extend(bedrock_sbom::python::parse_python(&inventory).unwrap_or_default());
                                
                                let sbom = bedrock_sbom::Sbom { packages };
                                
                                if format == "cyclonedx" {
                                    println!("{}", bedrock_sbom::cyclonedx::write_cyclonedx(&sbom));
                                } else {
                                    println!("{}", bedrock_sbom::spdx::write_spdx(&sbom));
                                }
                            }
                        }
                    }
                }
                _ => {
                    anyhow::bail!("not implemented");
                }
            }
        },
        Commands::Db { action } => {
            let mut db = bedrock_vuln::VulnerabilityDb::new().await.context("Failed to init DB")?;
            match action {
                DbAction::Update => {
                    anyhow::bail!("not implemented");
                }
                DbAction::Status => {
                    if let Some(meta) = db.status().context("Failed to check DB status")? {
                        println!("Database status: {} entries. Last update: {}", meta.entries_count, meta.updated_at);
                    } else {
                        println!("Database is empty. Run `bedrock db update`.");
                    }
                }
            }
        },
        Commands::Scan { .. } => {
            anyhow::bail!("not implemented");
        },
        Commands::Trace { .. } => {
            anyhow::bail!("not implemented");
        },
        Commands::Slim { .. } => {
            anyhow::bail!("not implemented");
        },
        Commands::Attest { .. } => {
            anyhow::bail!("not implemented");
        },
        Commands::Report { .. } => {
            anyhow::bail!("not implemented");
        }
    }

    Ok(())
}
