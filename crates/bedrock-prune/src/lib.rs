use std::collections::{HashSet, HashMap};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct KeepList {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub packages: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RemovalEvidence {
    pub package_name: String,
    pub removed_files: usize,
    pub kept_files: usize,
    pub reason: String,
}

#[derive(thiserror::Error, Debug)]
pub enum PruneError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),
}

pub type Result<T> = std::result::Result<T, PruneError>;

pub struct KeepSet {
    pub paths: HashSet<PathBuf>,
}

impl KeepSet {
    pub fn compute(
        trace: &bedrock_trace::ReachSet,
        keep_list: &KeepList,
        mandatory_paths: &[&Path],
        sbom: &bedrock_sbom::Sbom,
    ) -> Self {
        let mut paths = HashSet::new();
        
        // 1. Dynamic reach set
        paths.extend(trace.reached_paths.iter().cloned());
        
        // 2. Mandatory paths (e.g. /etc/passwd, /tmp)
        for p in mandatory_paths {
            paths.insert(p.to_path_buf());
        }
        
        // 3. Keep list paths
        for p in &keep_list.paths {
            paths.insert(PathBuf::from(p));
        }
        
        // 4. Keep list packages (all files owned by the package)
        let keep_pkgs: HashSet<_> = keep_list.packages.iter().collect();
        for pkg in &sbom.packages {
            if keep_pkgs.contains(&pkg.name) {
                paths.extend(pkg.files.iter().cloned());
            }
        }
        
        Self { paths }
    }
}

pub struct Assembler {
    output_dir: PathBuf,
}

impl Assembler {
    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }
    
    pub fn assemble(&self, _inventory: &bedrock_fs::FileInventory, keep_set: &KeepSet, _preserve_layers: bool) -> Result<Vec<RemovalEvidence>> {
        // Stub for assembling the final OCI image using fixed timestamps
        println!("Assembling pruned image into {}...", self.output_dir.display());
        println!("Keeping {} paths.", keep_set.paths.len());
        
        // Dummy evidence
        Ok(vec![
            RemovalEvidence {
                package_name: "curl".to_string(),
                removed_files: 10,
                kept_files: 0,
                reason: "Unreachable".to_string(),
            }
        ])
    }
}
