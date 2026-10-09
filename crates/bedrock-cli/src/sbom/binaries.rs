//! Packages that no package manager lists but a compiled binary carries:
//!
//! - **Go**: the module list and toolchain version the linker embeds
//!   (`runtime/debug.BuildInfo`), Go 1.18 and later. The standard library is
//!   reported as package `stdlib`, as OSV's Go feed names it.
//! - **Rust**: the dependency list `cargo auditable` compresses into the
//!   `.dep-v0` section. Binaries built with plain `cargo build` carry none.
//!
//! Executables are read once, in size-bounded batches per layer, so a large
//! image does not have to fit in memory.
use crate::fs::{EntryKind, FileInventory};
use crate::sbom::Package;
use anyhow::Result;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Smaller files cannot hold a Go runtime or a useful dependency list.
const MIN_BYTES: u64 = 256 << 10;
/// `FileInventory::extract_files` refuses single files above 256 MiB.
const MAX_BYTES: u64 = 200 << 20;
/// How much executable data is held in memory at once.
const BATCH_BYTES: u64 = 512 << 20;
const GO_MAGIC: &[u8] = b"\xff Go buildinf:";
const MODINFO_SENTINEL_LEN: usize = 16;

pub fn parse_binaries<F>(inventory: &FileInventory, resolver: F) -> Result<Vec<Package>>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    // Executable regular files, grouped by layer, in a stable order.
    let mut by_layer: BTreeMap<&str, Vec<(&PathBuf, u64)>> = BTreeMap::new();
    for (path, meta) in &inventory.files {
        if meta.kind == EntryKind::File
            && meta.mode & 0o111 != 0
            && (MIN_BYTES..=MAX_BYTES).contains(&meta.size)
        {
            by_layer.entry(meta.layer_digest.as_str()).or_default().push((path, meta.size));
        }
    }

    // (purl, name, version) -> binaries that carry it
    let mut found: BTreeMap<(String, String, String), Vec<PathBuf>> = BTreeMap::new();
    for (layer, mut files) in by_layer {
        let Some(tar) = resolver(layer) else { continue };
        files.sort();
        let mut batch: Vec<&Path> = Vec::new();
        let mut bytes = 0u64;
        let mut flush = |batch: &mut Vec<&Path>, bytes: &mut u64| -> Result<()> {
            if batch.is_empty() {
                return Ok(());
            }
            for (path, data) in inventory.extract_files(batch, &tar)? {
                for (purl_type, name, version) in detect(&data) {
                    found.entry((purl_type, name, version)).or_default().push(path.clone());
                }
            }
            batch.clear();
            *bytes = 0;
            Ok(())
        };
        for (path, size) in files {
            if bytes + size > BATCH_BYTES {
                flush(&mut batch, &mut bytes)?;
            }
            batch.push(path.as_path());
            bytes += size;
        }
        flush(&mut batch, &mut bytes)?;
    }

    Ok(found
        .into_iter()
        .map(|((ty, name, version), mut files)| {
            files.sort();
            files.dedup();
            Package {
                purl: format!("pkg:{ty}/{name}@{version}"),
                name,
                version,
                architecture: None,
                source: None,
                files,
            }
        })
        .collect())
}

/// `(purl type, name, version)` for everything one binary reports.
fn detect(data: &[u8]) -> Vec<(String, String, String)> {
    if let Some((go_version, modules)) = go_buildinfo(data) {
        let mut out = Vec::new();
        if let Some(v) = go_version.strip_prefix("go").filter(|v| !v.contains("devel")) {
            out.push(("golang".to_string(), "stdlib".to_string(), v.to_string()));
        }
        out.extend(modules.into_iter().map(|(n, v)| ("golang".to_string(), n, v)));
        return out;
    }
    rust_dependencies(data).into_iter().map(|(n, v)| ("cargo".to_string(), n, v)).collect()
}

fn uvarint(buf: &[u8]) -> Option<(usize, &[u8])> {
    let (mut value, mut shift) = (0usize, 0u32);
    for (i, &b) in buf.iter().enumerate().take(5) {
        value |= ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            return Some((value, &buf[i + 1..]));
        }
        shift += 7;
    }
    None
}

fn varint_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = uvarint(buf)?;
    (len <= rest.len()).then(|| rest.split_at(len))
}

/// The toolchain version and `(module path, version)` pairs of a Go binary
/// (build info with inline strings, Go 1.18 and later).
fn go_buildinfo(data: &[u8]) -> Option<(String, Vec<(String, String)>)> {
    let mut from = 0;
    while let Some(i) = data[from..].iter().position(|&b| b == GO_MAGIC[0]) {
        let at = from + i;
        from = at + 1;
        if !data[at..].starts_with(GO_MAGIC) {
            continue;
        }
        let header = data.get(at..at + 32)?;
        if header[15] & 2 == 0 {
            continue; // pointer-based strings (before Go 1.18): not supported
        }
        let (version, rest) = varint_string(&data[at + 32..])?;
        let version = String::from_utf8_lossy(version);
        let version = version.split_whitespace().next()?.to_string();
        if !version.starts_with("go") {
            continue;
        }
        let (modinfo, _) = varint_string(rest)?;
        let text = if modinfo.len() >= 2 * MODINFO_SENTINEL_LEN {
            &modinfo[MODINFO_SENTINEL_LEN..modinfo.len() - MODINFO_SENTINEL_LEN]
        } else {
            &[][..]
        };
        return Some((version, go_modules(&String::from_utf8_lossy(text))));
    }
    None
}

/// `mod`/`dep` lines of the build-info module table; `=>` replaces the line above it.
fn go_modules(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["mod" | "dep", path, version, ..] if !version.is_empty() && *version != "(devel)" => {
                out.push((path.to_string(), version.to_string()));
            }
            ["=>", path, version, ..] if !version.is_empty() => {
                if let Some(last) = out.last_mut() {
                    *last = (path.to_string(), version.to_string());
                }
            }
            _ => {}
        }
    }
    out
}

/// `(name, version)` of crates.io dependencies from a `cargo auditable` section.
fn rust_dependencies(data: &[u8]) -> Vec<(String, String)> {
    use goblin::elf::Elf;
    let Ok(elf) = Elf::parse(data) else { return Vec::new() };
    let Some(sh) =
        elf.section_headers.iter().find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".dep-v0"))
    else {
        return Vec::new();
    };
    let range = sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize;
    let Some(compressed) = data.get(range) else { return Vec::new() };
    let mut json = Vec::new();
    // The decompressed list is small; the cap stops a zip bomb.
    if flate2::read::ZlibDecoder::new(compressed).take(16 << 20).read_to_end(&mut json).is_err() {
        return Vec::new();
    }
    rust_packages(&json)
}

fn rust_packages(json: &[u8]) -> Vec<(String, String)> {
    #[derive(serde::Deserialize)]
    struct List {
        packages: Vec<Pkg>,
    }
    #[derive(serde::Deserialize)]
    struct Pkg {
        name: String,
        version: String,
        source: String,
    }
    serde_json::from_slice::<List>(json)
        .map(|l| {
            l.packages
                .into_iter()
                .filter(|p| p.source == "crates.io")
                .map(|p| (p.name, p.version))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn varint(n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut n = n;
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }

    /// A buffer shaped like a Go 1.18+ binary: padding, the 32-byte header, then
    /// the version and sentinel-wrapped module table as varint-prefixed strings.
    fn fake_go(version: &str, modinfo: &str) -> Vec<u8> {
        let mut b = vec![0xffu8; 7]; // 0xff bytes that are not the magic
        b.resize(64, 0);
        b.extend(GO_MAGIC);
        b.extend([8u8, 2u8]); // pointer size, flags: inline strings
        b.resize(b.len() + 16, 0);
        b.extend(varint(version.len()));
        b.extend(version.as_bytes());
        let wrapped = format!("{}{}{}", "S".repeat(16), modinfo, "E".repeat(16));
        b.extend(varint(wrapped.len()));
        b.extend(wrapped.as_bytes());
        b
    }

    #[test]
    fn reads_go_version_and_modules_including_replacements() {
        let modinfo = "path\texample.com/app\nmod\texample.com/app\t(devel)\t\n\
                       dep\tgolang.org/x/net\tv0.17.0\th1:abc\n\
                       dep\tgithub.com/old/lib\tv1.0.0\th1:def\n=>\tgithub.com/new/lib\tv1.2.0\th1:ghi\n";
        let found = detect(&fake_go("go1.21.4 X:nocoverageredesign", modinfo));
        assert!(found.contains(&("golang".into(), "stdlib".into(), "1.21.4".into())));
        assert!(found.contains(&("golang".into(), "golang.org/x/net".into(), "v0.17.0".into())));
        assert!(found.contains(&("golang".into(), "github.com/new/lib".into(), "v1.2.0".into())));
        assert!(!found.iter().any(|f| f.1 == "github.com/old/lib" || f.1 == "example.com/app"));
    }

    #[test]
    fn ignores_pre_1_18_build_info_devel_toolchains_and_plain_data() {
        let mut old = fake_go("go1.16", "dep\ta\tv1.0.0\t\n");
        let flag = old.windows(GO_MAGIC.len()).position(|w| w == GO_MAGIC).unwrap() + 15;
        old[flag] = 0; // pointer-based strings
        assert!(detect(&old).is_empty());
        assert!(!detect(&fake_go("go1.23-devel_abc", "")).iter().any(|f| f.1 == "stdlib"));
        assert!(detect(&[0xffu8; 4096]).is_empty());
        assert!(detect(b"").is_empty());
    }

    #[test]
    fn reads_cargo_auditable_dependency_list() {
        let json = br#"{"packages":[
            {"name":"app","version":"0.1.0","source":"local","root":true},
            {"name":"serde","version":"1.0.200","source":"crates.io"},
            {"name":"vendored","version":"2.0.0","source":"git"}]}"#;
        assert_eq!(rust_packages(json), [("serde".to_string(), "1.0.200".to_string())]);
        assert!(rust_packages(b"not json").is_empty());
        // The section holds zlib-compressed JSON.
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(json).unwrap();
        let compressed = z.finish().unwrap();
        let mut back = Vec::new();
        flate2::read::ZlibDecoder::new(&compressed[..]).read_to_end(&mut back).unwrap();
        assert_eq!(rust_packages(&back).len(), 1);
    }

    #[test]
    fn go_modules_skip_the_main_module_and_blank_versions() {
        let m = go_modules("path\tx\nmod\tx\t(devel)\t\ndep\ty\tv1.0.0\ts\ndep\tz\t\ts\n");
        assert_eq!(m, [("y".to_string(), "v1.0.0".to_string())]);
    }
}
