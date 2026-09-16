use std::path::{Path, PathBuf};
use crate::{Package, Result, SbomError};

pub fn parse_dpkg<F>(
    inventory: &bedrock_fs::FileInventory,
    resolver: F,
) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let status_path = Path::new("var/lib/dpkg/status");
    let mut packages = Vec::new();
    
    // Find status file in inventory
    let status_meta = match inventory.files.get(status_path) {
        Some(m) => m,
        None => return Ok(packages), // No dpkg installed
    };
    
    let tar_path = resolver(&status_meta.layer_digest)
        .ok_or_else(|| SbomError::Parse("Layer tarball not found".into()))?;
    
    let status_data = inventory.extract_file(status_path, &tar_path)?;
    let status_text = String::from_utf8_lossy(&status_data);
    
    let mut current_pkg: Option<String> = None;
    let mut current_ver: Option<String> = None;
    let mut current_arch: Option<String> = None;
    
    for line in status_text.lines() {
        if line.is_empty() {
            if let (Some(name), Some(ver), Some(arch)) = (&current_pkg, &current_ver, &current_arch) {
                let purl = format!("pkg:deb/debian/{}@{}?arch={}", name, ver, arch);
                
                // Find file list
                let list_path = PathBuf::from(format!("var/lib/dpkg/info/{}.list", name));
                let list_path_arch = PathBuf::from(format!("var/lib/dpkg/info/{}:{}.list", name, arch));
                
                let mut files = Vec::new();
                for lp in &[list_path, list_path_arch] {
                    if let Some(meta) = inventory.files.get(lp) {
                        if let Some(tp) = resolver(&meta.layer_digest) {
                            if let Ok(list_data) = inventory.extract_file(lp, &tp) {
                                let list_text = String::from_utf8_lossy(&list_data);
                                for f in list_text.lines() {
                                    if !f.trim().is_empty() {
                                        // dpkg list files start with / usually, but inventory paths are relative
                                        let clean_path = f.trim().strip_prefix('/').unwrap_or(f.trim());
                                        files.push(PathBuf::from(clean_path));
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
                
                packages.push(Package {
                    name: name.to_string(),
                    version: ver.to_string(),
                    architecture: Some(arch.to_string()),
                    purl,
                    files,
                });
            }
            current_pkg = None;
            current_ver = None;
            current_arch = None;
            continue;
        }
        
        if let Some(rest) = line.strip_prefix("Package: ") {
            current_pkg = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Version: ") {
            current_ver = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Architecture: ") {
            current_arch = Some(rest.trim().to_string());
        }
    }
    
    Ok(packages)
}
