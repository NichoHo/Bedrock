//! Accumulates what the tracee touched: which image paths were reached (with
//! evidence), and which it looked for and did not find.
use super::resolve::resolve;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Evidence kept per path; further distinct (syscall, process) pairs add nothing a reader needs.
const MAX_EVIDENCE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub syscall: String,
    pub process: String,
}

pub struct Recorder {
    root: PathBuf,
    /// Image path (leading `/`) -> evidence.
    pub reached: BTreeMap<PathBuf, Vec<Evidence>>,
    /// Paths looked up and not found (`ENOENT`/`ENOTDIR`) -> syscalls that tried.
    pub missing: BTreeMap<PathBuf, BTreeSet<String>>,
}

impl Recorder {
    pub fn new(root: &Path) -> Self {
        Self { root: root.to_path_buf(), reached: BTreeMap::new(), missing: BTreeMap::new() }
    }

    /// Records one syscall's outcome for `path` (absolute inside the image).
    /// Symlinks crossed are reached too; the final path only if it exists.
    pub fn record(
        &mut self,
        syscall: &str,
        process: &str,
        path: &Path,
        follow_last: bool,
        errno: Option<i32>,
    ) {
        // ENOENT, ENOTDIR
        let not_found = matches!(errno, Some(2 | 20));
        let Some(r) = resolve(&self.root, path, follow_last) else {
            self.add(syscall, process, absolute(path)); // symlink loop: keep the name asked for
            return;
        };
        for link in &r.links {
            self.add(syscall, process, absolute(link));
        }
        if not_found || !r.exists {
            self.missing.entry(absolute(path)).or_default().insert(syscall.to_string());
        } else {
            self.add(syscall, process, absolute(&r.real));
        }
    }

    fn add(&mut self, syscall: &str, process: &str, path: PathBuf) {
        let ev = Evidence { syscall: syscall.to_string(), process: process.to_string() };
        let list = self.reached.entry(path).or_default();
        if list.len() < MAX_EVIDENCE && !list.contains(&ev) {
            list.push(ev);
        }
    }
}

fn absolute(p: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in p.components() {
        if let std::path::Component::Normal(n) = c {
            out.push(n);
        }
    }
    out
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn records_links_final_path_and_misses() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("usr/lib")).unwrap();
        std::fs::write(t.path().join("usr/lib/libz.so.1.2"), b"x").unwrap();
        std::os::unix::fs::symlink("libz.so.1.2", t.path().join("usr/lib/libz.so.1")).unwrap();
        let mut r = Recorder::new(t.path());
        r.record("openat", "/usr/bin/app", Path::new("/usr/lib/libz.so.1"), true, None);
        r.record("openat", "/usr/bin/app", Path::new("/usr/lib/libz.so.1"), true, None); // deduped
        r.record("stat", "/usr/bin/app", Path::new("/etc/missing.conf"), true, Some(2));
        let reached: Vec<_> = r.reached.keys().map(|p| p.display().to_string()).collect();
        assert_eq!(reached, ["/usr/lib/libz.so.1", "/usr/lib/libz.so.1.2"]);
        assert_eq!(r.reached[Path::new("/usr/lib/libz.so.1.2")].len(), 1);
        assert!(r.missing.contains_key(Path::new("/etc/missing.conf")));
        assert!(!r.reached.contains_key(Path::new("/etc/missing.conf")));
    }
}
