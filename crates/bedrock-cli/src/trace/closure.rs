//! Static closure (BEDROCK_SPEC.md 5.5): everything a reached program needs
//! that a particular workload might never have exercised, such as the dynamic
//! loader and `DT_NEEDED` libraries it would map on first use, and the
//! interpreter named by a script's shebang.
use super::resolve::resolve;
use goblin::elf::Elf;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Programs bigger than this are not parsed for dependencies.
const MAX_PARSE_BYTES: u64 = 1 << 30;
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Why a path is in the closure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dep {
    /// `PT_INTERP`, `DT_NEEDED` or `shebang`.
    pub via: &'static str,
    /// The reached file that needs it (image path).
    pub needed_by: PathBuf,
}

/// Closure of `seeds` (image paths of reached files), as image path -> reasons.
/// Symlinks crossed to reach a dependency are included as paths of their own.
pub fn closure(
    root: &Path,
    seeds: &[PathBuf],
    ld_library_path: &[String],
) -> BTreeMap<PathBuf, Vec<Dep>> {
    let conf_dirs = ld_so_conf_dirs(root);
    let mut out: BTreeMap<PathBuf, Vec<Dep>> = BTreeMap::new();
    let mut seen: BTreeSet<PathBuf> = seeds.iter().cloned().collect();
    let mut queue: VecDeque<PathBuf> = seeds.iter().cloned().collect();

    while let Some(file) = queue.pop_front() {
        let Some(deps) = dependencies(root, &file, ld_library_path, &conf_dirs) else { continue };
        for (via, wanted) in deps {
            let Some(r) = resolve(root, &wanted, true).filter(|r| r.exists) else { continue };
            for p in r.links.into_iter().chain([r.real.clone()]) {
                let reasons = out.entry(p).or_default();
                let dep = Dep { via, needed_by: file.clone() };
                if !reasons.contains(&dep) {
                    reasons.push(dep);
                }
            }
            if seen.insert(r.real.clone()) {
                queue.push_back(r.real);
            }
        }
    }
    out
}

fn exists_in(root: &Path, p: &Path) -> bool {
    resolve(root, p, true).is_some_and(|r| r.exists)
}

/// Direct dependencies of one file as (reason, candidate image path).
fn dependencies(
    root: &Path,
    file: &Path,
    ld_library_path: &[String],
    conf_dirs: &[String],
) -> Option<Vec<(&'static str, PathBuf)>> {
    let host = root.join(file);
    let meta =
        std::fs::metadata(&host).ok().filter(|m| m.is_file() && m.len() <= MAX_PARSE_BYTES)?;
    let mut f = std::fs::File::open(&host).ok()?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic).ok()?;
    let mut deps = Vec::new();

    if n == 4 && &magic == b"\x7fELF" {
        let mut bytes = magic.to_vec();
        bytes.reserve(meta.len() as usize);
        f.read_to_end(&mut bytes).ok()?;
        let elf = Elf::parse(&bytes).ok()?;
        if let Some(interp) = elf.interpreter {
            deps.push(("PT_INTERP", PathBuf::from(interp)));
        }
        let origin = format!("/{}", file.parent().unwrap_or(Path::new("")).display());
        let split = |v: &[&str]| -> Vec<String> {
            v.iter()
                .flat_map(|s| s.split(':'))
                .filter(|s| !s.is_empty())
                .map(|s| expand(s, &origin, &elf))
                .collect()
        };
        let runpath = split(&elf.runpaths);
        // DT_RPATH is ignored when DT_RUNPATH exists, as ld.so does.
        let rpath = if runpath.is_empty() { split(&elf.rpaths) } else { Vec::new() };
        let triple = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x86_64-linux-gnu",
            goblin::elf::header::EM_AARCH64 => "aarch64-linux-gnu",
            _ => "",
        };
        let mut dirs: Vec<String> = rpath;
        dirs.extend(ld_library_path.iter().cloned());
        dirs.extend(runpath);
        dirs.extend(conf_dirs.iter().cloned());
        dirs.extend(["/lib", "/usr/lib", "/lib64", "/usr/lib64"].map(String::from));
        if !triple.is_empty() {
            dirs.push(format!("/lib/{triple}"));
            dirs.push(format!("/usr/lib/{triple}"));
        }
        for lib in &elf.libraries {
            let found = if lib.contains('/') {
                Some(PathBuf::from(lib))
            } else {
                dirs.iter().map(|d| Path::new(d).join(lib)).find(|c| exists_in(root, c))
            };
            if let Some(p) = found {
                deps.push(("DT_NEEDED", p));
            }
        }
    } else if n >= 2 && &magic[..2] == b"#!" {
        let mut head = magic.to_vec();
        f.take(256).read_to_end(&mut head).ok()?;
        let line = String::from_utf8_lossy(&head[2..]).into_owned();
        let mut words = line.lines().next().unwrap_or("").split_whitespace();
        let interp = words.next()?;
        if Path::new(interp).file_name().is_some_and(|n| n == "env") {
            // `#!/usr/bin/env [-S] [VAR=x] cmd`: the real interpreter is on PATH.
            if let Some(cmd) = words.find(|w| !w.starts_with('-') && !w.contains('=')) {
                let on_path = DEFAULT_PATH
                    .split(':')
                    .map(|d| Path::new(d).join(cmd))
                    .find(|c| exists_in(root, c));
                if let Some(p) = on_path {
                    deps.push(("shebang", p));
                }
            }
        }
        deps.push(("shebang", PathBuf::from(interp)));
    } else {
        return None;
    }
    Some(deps)
}

/// `$ORIGIN`, `$LIB` in RPATH entries.
fn expand(s: &str, origin: &str, elf: &Elf) -> String {
    let lib = if elf.is_64 { "lib64" } else { "lib" };
    s.replace("${ORIGIN}", origin)
        .replace("$ORIGIN", origin)
        .replace("${LIB}", lib)
        .replace("$LIB", lib)
}

/// Directories from `/etc/ld.so.conf`, following `include` globs of the
/// `dir/*.conf` form that distributions use.
fn ld_so_conf_dirs(root: &Path) -> Vec<String> {
    let mut dirs = Vec::new();
    let mut files = vec![PathBuf::from("etc/ld.so.conf")];
    let mut visited = 0;
    while let Some(conf) = files.pop() {
        visited += 1;
        if visited > 64 {
            break;
        }
        let Some(real) = resolve(root, &conf, true).filter(|r| r.exists) else { continue };
        let Ok(text) = std::fs::read_to_string(root.join(real.real)) else { continue };
        for line in
            text.lines().map(|l| l.split('#').next().unwrap_or("").trim()).filter(|l| !l.is_empty())
        {
            if let Some(pattern) = line.strip_prefix("include").map(str::trim) {
                let pattern = pattern.trim_start_matches('/');
                let Some((dir, glob)) = pattern.rsplit_once('/') else { continue };
                let suffix = glob.strip_prefix('*').unwrap_or(glob);
                let Some(d) = resolve(root, Path::new(dir), true).filter(|r| r.exists) else {
                    continue;
                };
                let mut names: Vec<String> = std::fs::read_dir(root.join(d.real))
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.ends_with(suffix))
                    .collect();
                names.sort();
                files.extend(names.into_iter().rev().map(|n| Path::new(dir).join(n)));
            } else {
                dirs.push(line.to_string());
            }
        }
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid ELF64 x86-64 executable: one PT_LOAD covering the file,
    /// PT_INTERP, PT_DYNAMIC, and DT_NEEDED entries for `needed`.
    fn fake_elf(interp: &str, needed: &[&str], runpath: Option<&str>) -> Vec<u8> {
        let mut strtab = vec![0u8];
        let mut add = |s: &str| -> u64 {
            let off = strtab.len() as u64;
            strtab.extend(s.as_bytes());
            strtab.push(0);
            off
        };
        let needed_offs: Vec<u64> = needed.iter().map(|n| add(n)).collect();
        let runpath_off = runpath.map(&mut add);
        let interp_bytes = [interp.as_bytes(), &[0]].concat();

        let phoff = 64u64;
        let phnum = 3u64;
        let interp_off = phoff + phnum * 56;
        let strtab_off = interp_off + interp_bytes.len() as u64;
        let dyn_off = (strtab_off + strtab.len() as u64).next_multiple_of(8);
        let mut dynamic: Vec<(u64, u64)> = needed_offs.iter().map(|&o| (1, o)).collect();
        if let Some(o) = runpath_off {
            dynamic.push((29, o)); // DT_RUNPATH
        }
        dynamic.extend([(5, strtab_off), (10, strtab.len() as u64), (0, 0)]); // STRTAB, STRSZ, NULL
        let total = dyn_off + dynamic.len() as u64 * 16;

        let mut b = Vec::new();
        b.extend(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
        b.extend(2u16.to_le_bytes()); // ET_EXEC
        b.extend(62u16.to_le_bytes()); // EM_X86_64
        b.extend(1u32.to_le_bytes());
        b.extend(0u64.to_le_bytes()); // entry
        b.extend(phoff.to_le_bytes());
        b.extend(0u64.to_le_bytes()); // shoff
        b.extend(0u32.to_le_bytes());
        b.extend(64u16.to_le_bytes());
        b.extend(56u16.to_le_bytes());
        b.extend((phnum as u16).to_le_bytes());
        b.extend(64u16.to_le_bytes());
        b.extend(0u16.to_le_bytes());
        b.extend(0u16.to_le_bytes());
        let phdr = |b: &mut Vec<u8>, ty: u32, off: u64, size: u64| {
            b.extend(ty.to_le_bytes());
            b.extend(4u32.to_le_bytes());
            for v in [off, off, off, size, size, 8] {
                b.extend(v.to_le_bytes());
            }
        };
        phdr(&mut b, 1, 0, total); // PT_LOAD, vaddr == file offset
        phdr(&mut b, 3, interp_off, interp_bytes.len() as u64); // PT_INTERP
        phdr(&mut b, 2, dyn_off, dynamic.len() as u64 * 16); // PT_DYNAMIC
        b.extend(&interp_bytes);
        b.extend(&strtab);
        b.resize(dyn_off as usize, 0);
        for (tag, val) in dynamic {
            b.extend(tag.to_le_bytes());
            b.extend(val.to_le_bytes());
        }
        b
    }

    fn put(root: &Path, rel: &str, data: &[u8]) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    fn keys(c: &BTreeMap<PathBuf, Vec<Dep>>) -> Vec<String> {
        c.keys().map(|p| p.display().to_string().replace('\\', "/")).collect()
    }

    #[test]
    fn parses_needed_interp_and_follows_ld_so_conf() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let ld = "/lib64/ld-linux-x86-64.so.2";
        put(r, "usr/bin/app", &fake_elf(ld, &["libfoo.so.1", "libmissing.so"], None));
        put(r, "lib64/ld-linux-x86-64.so.2", &fake_elf("", &[], None));
        put(r, "opt/foo/lib/libfoo.so.1", &fake_elf(ld, &["libbar.so"], None));
        put(r, "usr/lib/libbar.so", b"not elf");
        put(r, "etc/ld.so.conf", b"include /etc/ld.so.conf.d/*.conf\n");
        put(r, "etc/ld.so.conf.d/foo.conf", b"# comment\n/opt/foo/lib\n");

        let c = closure(r, &[PathBuf::from("usr/bin/app")], &[]);
        let k = keys(&c);
        assert!(k.contains(&"lib64/ld-linux-x86-64.so.2".to_string()), "{k:?}");
        assert!(k.contains(&"opt/foo/lib/libfoo.so.1".to_string()), "{k:?}");
        assert!(k.contains(&"usr/lib/libbar.so".to_string()), "{k:?}"); // transitive
        assert!(!k.iter().any(|k| k.contains("libmissing")), "{k:?}");
        assert_eq!(c[Path::new("opt/foo/lib/libfoo.so.1")][0].via, "DT_NEEDED");
    }

    #[test]
    fn runpath_with_origin_and_shebang_interpreters() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        put(r, "app/bin/tool", &fake_elf("/lib/ld.so", &["libx.so"], Some("$ORIGIN/../lib")));
        put(r, "lib/ld.so", &fake_elf("", &[], None));
        put(r, "app/lib/libx.so", b"data");
        put(r, "usr/bin/python3", &fake_elf("/lib/ld.so", &[], None));
        put(r, "app/run.py", b"#!/usr/bin/env python3\nprint(1)\n");
        put(r, "app/run.sh", b"#!/bin/sh\n");
        put(r, "bin/sh", &fake_elf("/lib/ld.so", &[], None));

        let seeds = ["app/bin/tool", "app/run.py", "app/run.sh"].map(PathBuf::from);
        let c = closure(r, &seeds, &[]);
        let k = keys(&c);
        for want in ["app/lib/libx.so", "usr/bin/python3", "bin/sh", "lib/ld.so"] {
            assert!(k.contains(&want.to_string()), "{want} missing from {k:?}");
        }
    }

    #[test]
    fn garbage_is_ignored_without_panicking() {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), "bin/bad", b"\x7fELF\x02\x01\x01 truncated");
        put(t.path(), "bin/empty", b"");
        let seeds = ["bin/bad", "bin/empty", "nope"].map(PathBuf::from);
        assert!(closure(t.path(), &seeds, &[]).is_empty());
    }
}
