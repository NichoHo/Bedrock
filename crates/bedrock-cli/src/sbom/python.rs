use crate::fs::{EntryKind, FileInventory};
use crate::sbom::{join_normalized, read_files, Package};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Reads the `Name:` and `Version:` fields out of a METADATA / PKG-INFO file
/// (RFC 822-ish key: value headers). Falls back to `None` per field if the
/// file is missing the header.
fn parse_metadata(data: &[u8]) -> (Option<String>, Option<String>) {
    let text = String::from_utf8_lossy(data);
    let mut name = None;
    let mut version = None;
    // Headers end at the first blank line; the long description follows.
    for line in text.lines().take_while(|l| !l.trim().is_empty()) {
        if let Some(v) = line.strip_prefix("Name:") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            version = Some(v.trim().to_string());
        }
    }
    (name, version)
}

/// PEP 503 name normalization, which is also what the pypi PURL type
/// requires: lowercase, with runs of `-`, `_` and `.` collapsed to `-`.
fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// The first field of a RECORD line, which is CSV: `path,hash,size`, with the
/// path double-quoted (and inner quotes doubled) if it contains a comma.
fn record_path(line: &str) -> Option<String> {
    let Some(quoted) = line.strip_prefix('"') else {
        return line.split(',').next().filter(|s| !s.is_empty()).map(str::to_string);
    };
    let mut out = String::new();
    let mut chars = quoted.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            if chars.peek() == Some(&'"') {
                chars.next();
            } else {
                return Some(out);
            }
        }
        out.push(c);
    }
    None
}

/// One installed distribution found in the image.
struct Dist {
    /// METADATA, PKG-INFO, or a single-file `.egg-info`.
    metadata: PathBuf,
    /// RECORD or installed-files.txt, if the format has one.
    file_list: Option<PathBuf>,
    /// Directory the file list's relative paths are relative to.
    list_base: PathBuf,
    /// `foo-1.0.dist-info` -> `foo`, used if metadata can't be read.
    fallback_name: String,
}

fn find_dists(inventory: &FileInventory) -> Vec<Dist> {
    let mut dists = Vec::new();
    for (path, meta) in &inventory.files {
        if meta.kind != EntryKind::File {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|f| f.to_str()) else { continue };
        let parent = path.parent().unwrap_or(Path::new(""));
        let parent_name = parent.file_name().and_then(|f| f.to_str()).unwrap_or("");
        let stem = |s: &str| s.split('-').next().unwrap_or(s).to_string();

        let dist = if file_name == "METADATA" && parent_name.ends_with(".dist-info") {
            Dist {
                metadata: path.clone(),
                file_list: Some(parent.join("RECORD")),
                list_base: parent.parent().unwrap_or(Path::new("")).to_path_buf(),
                fallback_name: stem(parent_name),
            }
        } else if file_name == "PKG-INFO" && parent_name.ends_with(".egg-info") {
            Dist {
                metadata: path.clone(),
                file_list: Some(parent.join("installed-files.txt")),
                list_base: parent.to_path_buf(),
                fallback_name: stem(parent_name),
            }
        } else if file_name.ends_with(".egg-info") {
            // Older distutils installs write PKG-INFO's contents to a single
            // `<name>-<version>.egg-info` file and record no file list.
            Dist {
                metadata: path.clone(),
                file_list: None,
                list_base: PathBuf::new(),
                fallback_name: stem(file_name),
            }
        } else {
            continue;
        };
        dists.push(dist);
    }
    dists.sort_by(|a, b| a.metadata.cmp(&b.metadata));
    dists
}

pub fn parse_python<F>(inventory: &FileInventory, resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let dists = find_dists(inventory);
    let wanted: Vec<PathBuf> = dists
        .iter()
        .flat_map(|d| std::iter::once(d.metadata.clone()).chain(d.file_list.clone()))
        .collect();
    let contents = read_files(inventory, &resolver, &wanted)?;

    let mut packages = Vec::new();
    for dist in dists {
        let (name, version) =
            contents.get(&dist.metadata).map(|d| parse_metadata(d)).unwrap_or((None, None));
        let name = name.unwrap_or(dist.fallback_name);
        let version = version.unwrap_or_else(|| "unknown".to_string());

        let mut files = vec![dist.metadata.clone()];
        if let Some(list) = dist.file_list.as_ref().and_then(|p| contents.get(p)) {
            for line in String::from_utf8_lossy(list).lines() {
                if let Some(rel) = record_path(line.trim()) {
                    files.extend(join_normalized(&dist.list_base, &rel));
                }
            }
        }
        files.sort();
        files.dedup();

        let purl = format!("pkg:pypi/{}@{}", normalize_name(&name), version);
        packages.push(Package { name, version, architecture: None, purl, files });
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_and_version_from_metadata() {
        let data =
            b"Metadata-Version: 2.1\nName: requests\nVersion: 2.25.1\nSummary: HTTP library\n";
        let (name, version) = parse_metadata(data);
        assert_eq!(name.as_deref(), Some("requests"));
        assert_eq!(version.as_deref(), Some("2.25.1"));
    }

    #[test]
    fn metadata_body_does_not_override_headers() {
        let data = b"Name: real\nVersion: 1.0\n\nVersion: 9.9 mentioned in the README\n";
        assert_eq!(parse_metadata(data).1.as_deref(), Some("1.0"));
    }

    #[test]
    fn pypi_names_are_pep503_normalized() {
        assert_eq!(normalize_name("Flask_SQLAlchemy"), "flask-sqlalchemy");
        assert_eq!(normalize_name("zope.interface"), "zope-interface");
        assert_eq!(normalize_name("a__-.b"), "a-b");
    }

    #[test]
    fn record_paths_handle_csv_quoting() {
        assert_eq!(
            record_path("requests/api.py,sha256=abc,123").as_deref(),
            Some("requests/api.py")
        );
        assert_eq!(record_path("\"odd,name.py\",sha256=abc,1").as_deref(), Some("odd,name.py"));
        assert_eq!(record_path("\"say \"\"hi\"\".py\",,").as_deref(), Some("say \"hi\".py"));
        assert_eq!(record_path(""), None);
    }
}
