//! Version comparison, one scheme per ecosystem. They disagree on purpose:
//! dpkg sorts `1.0~rc1` before `1.0`, rpm treats `^` as "after", apk has
//! `_p1` patch suffixes, and PEP 440 has epochs and `.devN`. Comparing any of
//! them as plain strings or as semver gives wrong answers.
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Dpkg,
    Apk,
    Rpm,
    Semver,
    Pep440,
}

pub fn compare(scheme: Scheme, a: &str, b: &str) -> Ordering {
    match scheme {
        Scheme::Dpkg => dpkg(a, b),
        Scheme::Apk => apk(a, b),
        Scheme::Rpm => rpm(a, b),
        Scheme::Semver => semver(a, b),
        Scheme::Pep440 => pep440(a, b),
    }
}

// ---------------------------------------------------------------- dpkg

fn split_epoch(v: &str) -> (u64, &str) {
    match v.split_once(':') {
        Some((e, rest)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => {
            (e.parse().unwrap_or(u64::MAX), rest)
        }
        _ => (0, v),
    }
}

pub fn dpkg(a: &str, b: &str) -> Ordering {
    let ((ea, a), (eb, b)) = (split_epoch(a), split_epoch(b));
    let split_rev = |v: &'_ str| match v.rsplit_once('-') {
        Some((u, r)) => (u.to_string(), r.to_string()),
        None => (v.to_string(), String::new()),
    };
    let ((ua, ra), (ub, rb)) = (split_rev(a), split_rev(b));
    ea.cmp(&eb)
        .then_with(|| dpkg_part(ua.as_bytes(), ub.as_bytes()))
        .then_with(|| dpkg_part(ra.as_bytes(), rb.as_bytes()))
}

/// dpkg's `verrevcmp`: alternating non-digit and digit runs, where `~` sorts
/// before everything (even the empty string) and letters before punctuation.
fn dpkg_part(a: &[u8], b: &[u8]) -> Ordering {
    fn order(c: Option<u8>) -> i32 {
        match c {
            None => 0,
            Some(b'~') => -1,
            Some(c) if c.is_ascii_digit() => 0,
            Some(c) if c.is_ascii_alphabetic() => c as i32,
            Some(c) => c as i32 + 256,
        }
    }
    let is_digit = |s: &[u8], i: usize| s.get(i).is_some_and(u8::is_ascii_digit);
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while (i < a.len() && !is_digit(a, i)) || (j < b.len() && !is_digit(b, j)) {
            let (x, y) = (order(a.get(i).copied()), order(b.get(j).copied()));
            if x != y {
                return x.cmp(&y);
            }
            i += 1;
            j += 1;
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while is_digit(a, i) && is_digit(b, j) {
            if first_diff == Ordering::Equal {
                first_diff = a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
        if is_digit(a, i) {
            return Ordering::Greater;
        }
        if is_digit(b, j) {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

// ----------------------------------------------------------------- rpm

pub fn rpm(a: &str, b: &str) -> Ordering {
    let ((ea, a), (eb, b)) = (split_epoch(a), split_epoch(b));
    let split_rel = |v: &'_ str| match v.rsplit_once('-') {
        Some((ver, rel)) => (ver.to_string(), Some(rel.to_string())),
        None => (v.to_string(), None),
    };
    let ((va, ra), (vb, rb)) = (split_rel(a), split_rel(b));
    ea.cmp(&eb).then_with(|| rpmvercmp(&va, &vb)).then_with(|| match (ra, rb) {
        (Some(x), Some(y)) => rpmvercmp(&x, &y),
        _ => Ordering::Equal, // a missing release matches any release, as in rpm
    })
}

/// rpm's `rpmvercmp`: compare alternating numeric and alphabetic segments,
/// numeric beats alphabetic, `~` sorts before the end and `^` just after it.
fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    let skip = |s: &mut &[u8]| {
        while let Some(&c) = s.first() {
            if c.is_ascii_alphanumeric() || c == b'~' || c == b'^' {
                break;
            }
            *s = &s[1..];
        }
    };
    loop {
        skip(&mut a);
        skip(&mut b);
        match (a.first() == Some(&b'~'), b.first() == Some(&b'~')) {
            (true, true) => {
                a = &a[1..];
                b = &b[1..];
                continue;
            }
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            _ => {}
        }
        match (a.first() == Some(&b'^'), b.first() == Some(&b'^')) {
            (true, true) => {
                a = &a[1..];
                b = &b[1..];
                continue;
            }
            (true, false) => {
                return if b.is_empty() { Ordering::Greater } else { Ordering::Less };
            }
            (false, true) => {
                return if a.is_empty() { Ordering::Less } else { Ordering::Greater };
            }
            _ => {}
        }
        if a.is_empty() || b.is_empty() {
            break;
        }
        let numeric = a[0].is_ascii_digit();
        let take = |s: &mut &[u8]| -> Vec<u8> {
            let n = s
                .iter()
                .take_while(|c| if numeric { c.is_ascii_digit() } else { c.is_ascii_alphabetic() })
                .count();
            let (seg, rest) = s.split_at(n);
            *s = rest;
            seg.to_vec()
        };
        let (sa, sb) = (take(&mut a), take(&mut b));
        if sb.is_empty() {
            // segments of different kinds: numeric is newer
            return if numeric { Ordering::Greater } else { Ordering::Less };
        }
        let ord = if numeric {
            let (x, y) = (trim_zeros(&sa), trim_zeros(&sb));
            x.len().cmp(&y.len()).then_with(|| x.cmp(y))
        } else {
            sa.cmp(&sb)
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    match (a.is_empty(), b.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

fn trim_zeros(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&c| c == b'0').count();
    &s[n..]
}

// ----------------------------------------------------------------- apk

/// Alpine versions: `1.2.3[letter][_suffix[N]]...[-rN]`.
#[derive(Default)]
struct Apk {
    nums: Vec<u64>,
    letter: u8,
    suffixes: Vec<(i32, u64)>,
    rev: u64,
}

fn apk_suffix_rank(s: &str) -> i32 {
    match s {
        "alpha" => -4,
        "beta" => -3,
        "pre" => -2,
        "rc" => -1,
        "cvs" => 1,
        "svn" => 2,
        "git" => 3,
        "hg" => 4,
        "p" => 5,
        _ => 0,
    }
}

fn parse_apk(v: &str) -> Apk {
    let mut out = Apk::default();
    let (main, rev) = match v.rsplit_once("-r") {
        Some((m, r)) if r.bytes().all(|b| b.is_ascii_digit()) && !r.is_empty() => {
            (m, r.parse().unwrap_or(0))
        }
        _ => (v, 0),
    };
    out.rev = rev;
    let mut parts = main.split('_');
    let head = parts.next().unwrap_or("");
    let digits_end = head.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(head.len());
    out.nums = head[..digits_end]
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap_or(0))
        .collect();
    out.letter = head[digits_end..].bytes().next().unwrap_or(0);
    for s in parts {
        let name_end = s.find(|c: char| c.is_ascii_digit()).unwrap_or(s.len());
        out.suffixes.push((apk_suffix_rank(&s[..name_end]), s[name_end..].parse().unwrap_or(0)));
    }
    out
}

pub fn apk(a: &str, b: &str) -> Ordering {
    let (x, y) = (parse_apk(a), parse_apk(b));
    // ponytail: apk compares a component with a leading zero ("1.02") as a
    // fraction, not a number. Rare in practice; plain numeric compare here.
    let n = x.nums.len().max(y.nums.len());
    for i in 0..n {
        let o = x.nums.get(i).unwrap_or(&0).cmp(y.nums.get(i).unwrap_or(&0));
        if o != Ordering::Equal {
            return o;
        }
    }
    x.letter.cmp(&y.letter).then_with(|| {
        let n = x.suffixes.len().max(y.suffixes.len());
        for i in 0..n {
            let o = x.suffixes.get(i).unwrap_or(&(0, 0)).cmp(y.suffixes.get(i).unwrap_or(&(0, 0)));
            if o != Ordering::Equal {
                return o;
            }
        }
        x.rev.cmp(&y.rev)
    })
}

// -------------------------------------------------------------- semver

pub fn semver(a: &str, b: &str) -> Ordering {
    let (ca, pa) = semver_parts(a);
    let (cb, pb) = semver_parts(b);
    ca.cmp(&cb).then_with(|| match (pa.is_empty(), pb.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater, // a release outranks its prereleases
        (false, true) => Ordering::Less,
        (false, false) => {
            for (x, y) in pa.iter().zip(&pb) {
                let o = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    (Ok(_), Err(_)) => Ordering::Less, // numeric ids sort before alphanumeric
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
            pa.len().cmp(&pb.len())
        }
    })
}

/// `([major, minor, patch], prerelease identifiers)`. Lenient: a leading `v`,
/// missing minor/patch and build metadata are tolerated, since npm and Go
/// versions in the wild are not all strict semver.
fn semver_parts(v: &str) -> ([u64; 3], Vec<String>) {
    let v = v.trim().trim_start_matches(['v', '=']);
    let v = v.split('+').next().unwrap_or("");
    let (core, pre) = v.split_once('-').unwrap_or((v, ""));
    let mut c = [0u64; 3];
    for (i, p) in core.split('.').take(3).enumerate() {
        c[i] = p.parse().unwrap_or(0);
    }
    (c, pre.split('.').filter(|s| !s.is_empty()).map(String::from).collect())
}

// -------------------------------------------------------------- PEP 440

pub fn pep440(a: &str, b: &str) -> Ordering {
    pep440_key(a).cmp(&pep440_key(b))
}

type Pep440Key = (u64, Vec<u64>, (i64, u64), i64, i64);

/// Mirrors `packaging.version`'s sort key. Local versions (`+abc`) are ignored.
fn pep440_key(v: &str) -> Pep440Key {
    let v = v.trim().to_ascii_lowercase();
    let v = v.trim_start_matches('v');
    let v = v.split('+').next().unwrap_or("");
    let (epoch, v) = match v.split_once('!') {
        Some((e, rest)) => (e.parse().unwrap_or(0), rest),
        None => (0, v),
    };
    let rel_end = v.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(v.len());
    let mut release: Vec<u64> =
        v[..rel_end].split('.').filter(|s| !s.is_empty()).map(|s| s.parse().unwrap_or(0)).collect();
    while release.len() > 1 && release.last() == Some(&0) {
        release.pop();
    }
    let mut rest = v[rel_end..].trim_start_matches(['.', '-', '_']);
    let (mut pre, mut post, mut dev): (Option<(i64, u64)>, Option<u64>, Option<u64>) =
        (None, None, None);
    while !rest.is_empty() {
        let word_end = rest.find(|c: char| !c.is_ascii_alphabetic()).unwrap_or(rest.len());
        let (word, after) = rest.split_at(word_end);
        let after = after.trim_start_matches(['.', '-', '_']);
        let num_end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
        let n: u64 = after[..num_end].parse().unwrap_or(0);
        match word {
            "a" | "alpha" => pre = Some((0, n)),
            "b" | "beta" => pre = Some((1, n)),
            "c" | "rc" | "pre" | "preview" => pre = Some((2, n)),
            "post" | "rev" | "r" => post = Some(n),
            "" if !after.is_empty() && num_end > 0 => post = Some(n), // implicit "-N" post release
            "dev" => dev = Some(n),
            _ => {}
        }
        let next = after[num_end..].trim_start_matches(['.', '-', '_']);
        if next.len() == rest.len() {
            break;
        }
        rest = next;
    }
    let pre_key = match (pre, post, dev) {
        (None, None, Some(_)) => (-1, 0), // 1.0.dev1 sorts before 1.0a1
        (None, _, _) => (3, 0),
        (Some(p), _, _) => p,
    };
    (epoch, release, pre_key, post.map_or(-1, |p| p as i64), dev.map_or(i64::MAX, |d| d as i64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    #[test]
    fn dpkg_ordering() {
        assert_eq!(dpkg("1.0~rc1", "1.0"), Less);
        assert_eq!(dpkg("1:0.5", "2.0"), Greater); // epoch wins
        assert_eq!(dpkg("5.10", "5.9"), Greater);
        assert_eq!(dpkg("1.0-1", "1.0-1"), Equal);
        assert_eq!(dpkg("3.0.11-1~deb12u2", "3.0.11-1~deb12u1"), Greater);
        assert_eq!(dpkg("3.0.11-1~deb12u2", "3.0.11-1"), Less);
        assert_eq!(dpkg("2.36-9+deb12u3+b1", "2.36-9+deb12u3"), Greater);
        assert_eq!(dpkg("1.0a", "1.0"), Greater);
        assert_eq!(dpkg("1.0+b1", "1.0"), Greater);
    }

    #[test]
    fn rpm_ordering() {
        assert_eq!(rpm("5.10", "5.9"), Greater);
        assert_eq!(rpm("1.0~rc1", "1.0"), Less);
        assert_eq!(rpm("1.0^git1", "1.0"), Greater);
        assert_eq!(rpm("1.0^git1", "1.0.1"), Less);
        assert_eq!(rpm("1:1.0-1", "2.0-1"), Greater);
        assert_eq!(rpm("0:4.18.0-477.27.1.el8_8", "4.18.0-477.27.1.el8_8"), Equal);
        assert_eq!(rpm("4.18.0-305.103.1.el8_4", "4.18.0-477.27.1.el8_8"), Less);
        assert_eq!(rpm("1.0a", "1.0"), Greater);
        assert_eq!(rpm("1.0", "1.0a"), Less);
        assert_eq!(rpm("2.0.1", "2.0.1.1"), Less);
        assert_eq!(rpm("1.01", "1.1"), Equal);
        assert_eq!(rpm("1.a", "1.1"), Less); // numeric beats alpha
    }

    #[test]
    fn apk_ordering() {
        assert_eq!(apk("1.2.4-r2", "1.2.4-r10"), Less);
        assert_eq!(apk("1.2.4-r0", "1.2.3-r9"), Greater);
        assert_eq!(apk("1.2.3_rc1", "1.2.3"), Less);
        assert_eq!(apk("1.2.3_p1", "1.2.3"), Greater);
        assert_eq!(apk("1.2.3a", "1.2.3"), Greater);
        assert_eq!(apk("1.2.3_alpha", "1.2.3_beta"), Less);
        assert_eq!(apk("3.9.1-r0", "3.10.0-r0"), Less);
        assert_eq!(apk("1.1.1w-r1", "1.1.1v-r5"), Greater);
    }

    #[test]
    fn semver_ordering() {
        assert_eq!(semver("1.10.0", "1.9.0"), Greater);
        assert_eq!(semver("1.0.0-rc.1", "1.0.0"), Less);
        assert_eq!(semver("1.0.0-alpha.2", "1.0.0-alpha.10"), Less);
        assert_eq!(semver("1.0.0-alpha", "1.0.0-alpha.1"), Less);
        assert_eq!(semver("v2.0", "2.0.0"), Equal);
        assert_eq!(semver("1.0.0+build5", "1.0.0"), Equal);
        assert_eq!(semver("1.0.0-1", "1.0.0-a"), Less);
    }

    #[test]
    fn pep440_ordering() {
        assert_eq!(pep440("2.31.0", "2.9.0"), Greater);
        assert_eq!(pep440("1.0rc1", "1.0"), Less);
        assert_eq!(pep440("1.0.dev1", "1.0a1"), Less);
        assert_eq!(pep440("1.0.post1", "1.0"), Greater);
        assert_eq!(pep440("1.0", "1.0.0"), Equal);
        assert_eq!(pep440("1!0.5", "2.0"), Greater);
        assert_eq!(pep440("1.0a1", "1.0b1"), Less);
        assert_eq!(pep440("1.0b2", "1.0rc1"), Less);
        assert_eq!(pep440("1.0+local", "1.0"), Equal);
        assert_eq!(pep440("1.0-1", "1.0.post1"), Equal);
    }
}
