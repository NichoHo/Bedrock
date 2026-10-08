//! Minimal glob matching for keep-list and mandatory paths. Paths and
//! patterns are `/`-separated with no leading slash. `*` and `?` match within
//! one segment; `**` matches any number of whole segments, including none, so
//! `a/b/**` also matches `a/b` itself.

pub fn matches(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let segs: Vec<&str> = path.split('/').collect();
    walk(&pat, &segs)
}

fn walk(pat: &[&str], segs: &[&str]) -> bool {
    match pat.split_first() {
        None => segs.is_empty(),
        Some((&"**", rest)) => (0..=segs.len()).any(|skip| walk(rest, &segs[skip..])),
        Some((p, rest)) => match segs.split_first() {
            Some((s, tail)) => segment(p.as_bytes(), s.as_bytes()) && walk(rest, tail),
            None => false,
        },
    }
}

/// `*` and `?` within a single path segment.
fn segment(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn globs() {
        assert!(matches("etc/passwd", "etc/passwd"));
        assert!(!matches("etc/passwd", "etc/passwd2"));
        assert!(matches("app/locales/**", "app/locales/en/messages.mo"));
        assert!(matches("app/locales/**", "app/locales"));
        assert!(!matches("app/locales/**", "app/localesx/a"));
        assert!(matches("lib*/ld-linux*", "lib64/ld-linux-x86-64.so.2"));
        assert!(matches("lib/**/libc.so*", "lib/x86_64-linux-gnu/libc.so.6"));
        assert!(matches("lib/**/libc.so*", "lib/libc.so.6"));
        assert!(!matches("lib/**/libc.so*", "lib/x86_64-linux-gnu/libcurl.so.4"));
        assert!(matches("usr/share/zoneinfo/Asia/**", "usr/share/zoneinfo/Asia/Tokyo"));
        assert!(matches("a/?/c", "a/b/c"));
        assert!(!matches("a/?/c", "a/bb/c"));
        assert!(matches("**/*.pyc", "usr/lib/python3/x/y.pyc"));
    }
}
