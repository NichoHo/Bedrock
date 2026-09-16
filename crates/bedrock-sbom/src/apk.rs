use std::path::{Path, PathBuf};
use crate::{Package, Result, SbomError};

pub fn parse_apk<F>(
    inventory: &bedrock_fs::FileInventory,
    resolver: F,
) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let db_path = Path::new("lib/apk/db/installed");
    let mut packages = Vec::new();
    
    let db_meta = match inventory.files.get(db_path) {
        Some(m) => m,
        None => return Ok(packages), // No apk installed
    };
    
    let tar_path = resolver(&db_meta.layer_digest)
        .ok_or_else(|| SbomError::Parse("Layer tarball not found".into()))?;
    
    let db_data = inventory.extract_file(db_path, &tar_path)?;
    let db_text = String::from_utf8_lossy(&db_data);
    
    let mut current_pkg: Option<String> = None;
    let mut current_ver: Option<String> = None;
    let mut current_arch: Option<String> = None;
    let mut current_files: Vec<PathBuf> = Vec::new();
    let mut current_dir = String::new();
    
    for line in db_text.lines() {
        if line.is_empty() {
            if let (Some(name), Some(ver)) = (&current_pkg, &current_ver) {
                let arch_str = current_arch.clone().unwrap_or_else(|| "x86_64".to_string());
                let purl = format!("pkg:apk/alpine/{}@{}?arch={}", name, ver, arch_str);
                
                packages.push(Package {
                    name: name.to_string(),
                    version: ver.to_string(),
                    architecture: current_arch.clone(),
                    purl,
                    files: current_files.clone(),
                });
            }
            current_pkg = None;
            current_ver = None;
            current_arch = None;
            current_files.clear();
            current_dir.clear();
            continue;
        }
        
        if let Some(rest) = line.strip_prefix("P:") {
            current_pkg = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("V:") {
            current_ver = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("A:") {
            current_arch = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("F:") {
            current_dir = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("R:") {
            let file_path = if current_dir.is_empty() {
                rest.trim().to_string()
            } else {
                format!("{}/{}", current_dir, rest.trim())
            };
            current_files.push(PathBuf::from(file_path));
        }
    }
    
    // Handle last block
    if let (Some(name), Some(ver)) = (&current_pkg, &current_ver) {
        let arch_str = current_arch.clone().unwrap_or_else(|| "x86_64".to_string());
        let purl = format!("pkg:apk/alpine/{}@{}?arch={}", name, ver, arch_str);
        
        packages.push(Package {
            name: name.to_string(),
            version: ver.to_string(),
            architecture: current_arch.clone(),
            purl,
            files: current_files.clone(),
        });
    }
    
    Ok(packages)
}
