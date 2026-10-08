//! chroot-style path resolution against an extracted rootfs on the host.
//!
//! Symlinks are followed as the tracee's kernel would inside the chroot:
//! absolute targets restart at the image root and `..` cannot climb above it.
//! Every symlink crossed is reported, because a pruned image that keeps
//! `libc.so.6` but drops the link it was reached through is broken.
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

const MAX_LINKS: usize = 40;

#[derive(Debug, PartialEq, Eq)]
pub struct Resolved {
    /// Final path inside the image, no leading slash, no symlinks in it
    /// (except possibly the last component when `follow_last` is false).
    pub real: PathBuf,
    /// Every symlink crossed on the way, as image paths.
    pub links: Vec<PathBuf>,
    pub exists: bool,
}

/// Resolves `path` (absolute inside the image, or relative to its root).
/// Returns `None` after too many symlinks (a loop).
pub fn resolve(root: &Path, path: &Path, follow_last: bool) -> Option<Resolved> {
    let mut work: Vec<OsString> = components(path);
    work.reverse();
    let mut stack: Vec<OsString> = Vec::new();
    let mut links = Vec::new();
    let mut hops = 0;
    let mut exists = true;

    while let Some(name) = work.pop() {
        if name == ".." {
            stack.pop();
            continue;
        }
        stack.push(name);
        if !exists {
            continue;
        }
        let host = stack.iter().fold(root.to_path_buf(), |p, c| p.join(c));
        match std::fs::symlink_metadata(&host) {
            Err(_) => exists = false,
            Ok(m) if m.file_type().is_symlink() => {
                if work.is_empty() && !follow_last {
                    break;
                }
                hops += 1;
                if hops > MAX_LINKS {
                    return None;
                }
                links.push(stack.iter().collect());
                let target = std::fs::read_link(&host).ok()?;
                stack.pop();
                if target.is_absolute() {
                    stack.clear();
                }
                work.extend(components(&target).into_iter().rev());
            }
            Ok(_) => {}
        }
    }
    Some(Resolved { real: stack.iter().collect(), links, exists })
}

fn components(p: &Path) -> Vec<OsString> {
    p.components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_owned()),
            Component::ParentDir => Some("..".into()),
            _ => None,
        })
        .collect()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn rootfs() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        std::fs::create_dir_all(r.join("usr/lib")).unwrap();
        std::fs::write(r.join("usr/lib/libc-2.31.so"), b"x").unwrap();
        symlink("libc-2.31.so", r.join("usr/lib/libc.so.6")).unwrap();
        symlink("usr/lib", r.join("lib")).unwrap(); // merged-usr
        symlink("/usr/lib", r.join("abs")).unwrap();
        symlink("../../../../../usr/lib", r.join("escape")).unwrap();
        symlink("loop", r.join("loop")).unwrap();
        t
    }

    #[test]
    fn follows_relative_and_directory_symlinks_and_reports_each() {
        let t = rootfs();
        let r = resolve(t.path(), Path::new("/lib/libc.so.6"), true).unwrap();
        assert_eq!(r.real, Path::new("usr/lib/libc-2.31.so"));
        assert_eq!(r.links, [PathBuf::from("lib"), PathBuf::from("usr/lib/libc.so.6")]);
        assert!(r.exists);
    }

    #[test]
    fn absolute_targets_stay_inside_the_image_and_dotdot_cannot_escape() {
        let t = rootfs();
        assert_eq!(
            resolve(t.path(), Path::new("/abs/libc.so.6"), true).unwrap().real,
            Path::new("usr/lib/libc-2.31.so")
        );
        assert_eq!(
            resolve(t.path(), Path::new("/escape/libc-2.31.so"), true).unwrap().real,
            Path::new("usr/lib/libc-2.31.so")
        );
        assert_eq!(
            resolve(t.path(), Path::new("/../../usr/lib"), true).unwrap().real,
            Path::new("usr/lib")
        );
    }

    #[test]
    fn nofollow_keeps_the_final_link_and_missing_paths_are_flagged() {
        let t = rootfs();
        let r = resolve(t.path(), Path::new("/lib/libc.so.6"), false).unwrap();
        assert_eq!(r.real, Path::new("usr/lib/libc.so.6"));
        let m = resolve(t.path(), Path::new("/usr/lib/nope/x"), true).unwrap();
        assert!(!m.exists);
        assert_eq!(m.real, Path::new("usr/lib/nope/x"));
    }

    #[test]
    fn loops_give_up() {
        let t = rootfs();
        assert!(resolve(t.path(), Path::new("/loop"), true).is_none());
    }
}
