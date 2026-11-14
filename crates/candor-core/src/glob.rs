//! Path patterns for rule classes and allowlist entries.
//!
//! A pattern is compared one path component at a time: `*` matches any run
//! of bytes inside one component and never crosses `/`. A pattern with no
//! `/` at all is compared with the last component (the file name) only.
//! Matching works on raw bytes because paths need not be UTF-8 (I5).

/// Wildcard match of one component: `*` matches any bytes.
fn component_matches(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while i < s.len() {
        match pat.get(p) {
            Some(b'*') => {
                star = Some((p, i));
                p += 1;
            }
            Some(&c) if Some(&c) == s.get(i) => {
                p += 1;
                i += 1;
            }
            _ => match star {
                Some((sp, si)) => {
                    p = sp + 1;
                    i = si + 1;
                    star = Some((sp, si + 1));
                }
                None => return false,
            },
        }
    }
    while pat.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pat.len()
}

/// True if `path` matches `pattern` (see the module comment).
pub fn matches(pattern: &[u8], path: &[u8]) -> bool {
    if !pattern.contains(&b'/') {
        let name = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
        return component_matches(pattern, name);
    }
    let mut ps = pattern.split(|&b| b == b'/');
    let mut ss = path.split(|&b| b == b'/');
    loop {
        match (ps.next(), ss.next()) {
            (None, None) => return true,
            (Some(p), Some(s)) if component_matches(p, s) => {}
            _ => return false,
        }
    }
}

/// Expands a leading "~/" to `home` + "/".
pub fn expand_home(pattern: &str, home: &[u8]) -> Vec<u8> {
    match pattern.strip_prefix("~/") {
        Some(rest) => {
            let mut v = home.to_vec();
            v.push(b'/');
            v.extend_from_slice(rest.as_bytes());
            v
        }
        None => pattern.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_and_stars() {
        assert!(matches(b"/home/u/.ssh/id_*", b"/home/u/.ssh/id_ed25519"));
        assert!(!matches(b"/home/u/.ssh/id_*", b"/home/u/.ssh/sub/id_x"));
        assert!(matches(b"/etc/cron*", b"/etc/crontab"));
        assert!(matches(b"/etc/cron*/*", b"/etc/cron.d/job"));
        assert!(!matches(b"/etc/cron*", b"/etc/cron.d/job"));
        assert!(matches(b"*.kdbx", b"/home/u/vault/my.kdbx"));
        assert!(matches(
            b"/usr/lib/firefox*/firefox*",
            b"/usr/lib/firefox-esr/firefox-esr"
        ));
        assert!(matches(b"a*b*c", b"aXXbYYc"));
        assert!(!matches(b"a*b*c", b"aXXbYY"));
        assert!(matches(b"/x/\xff*", b"/x/\xff\xfe"));
    }

    #[test]
    fn home_expansion() {
        assert_eq!(
            expand_home("~/.ssh/id_*", b"/home/u"),
            b"/home/u/.ssh/id_*".to_vec()
        );
        assert_eq!(
            expand_home("/etc/shadow", b"/home/u"),
            b"/etc/shadow".to_vec()
        );
    }
}
