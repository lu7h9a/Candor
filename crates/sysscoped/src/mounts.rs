//! Mount points by device, from /proc/self/mountinfo.
//!
//! RENAME and UNLINK paths come from a dentry walk that stops at the root of
//! the filesystem, so the daemon puts the mount point in front. When a
//! device is mounted more than once (bind mounts) the mount of the
//! filesystem's own root ("/" in field 4) is preferred. The result is
//! display data only and is marked approximate (invariant I5).

use std::collections::BTreeMap;

/// Mount point bytes by (major, minor).
#[derive(Clone, Debug, Default)]
pub struct Mounts {
    by_dev: BTreeMap<(u32, u32), Vec<u8>>,
}

/// Decodes the octal escapes mountinfo uses for spaces and other bytes.
fn unescape_octal(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while let Some(&b) = field.get(i) {
        let digits = field.get(i + 1..i + 4);
        if b == b'\\'
            && let Some(d) = digits
            && d.iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = d.iter().fold(0u32, |acc, c| acc * 8 + u32::from(c - b'0'));
            out.push((v & 0xff) as u8);
            i += 4;
            continue;
        }
        out.push(b);
        i += 1;
    }
    out
}

impl Mounts {
    /// Parses the text of /proc/self/mountinfo. Malformed lines are skipped.
    pub fn parse(text: &[u8]) -> Mounts {
        let mut m = Mounts::default();
        for line in text.split(|&b| b == b'\n') {
            let f: Vec<&[u8]> = line.split(|&b| b == b' ').collect();
            let (Some(majmin), Some(root), Some(point)) = (f.get(2), f.get(3), f.get(4)) else {
                continue;
            };
            let s = String::from_utf8_lossy(majmin);
            let Some((a, b)) = s.split_once(':') else {
                continue;
            };
            let (Ok(major), Ok(minor)) = (a.parse::<u32>(), b.parse::<u32>()) else {
                continue;
            };
            let point = unescape_octal(point);
            let is_root = *root == b"/";
            if is_root || !m.by_dev.contains_key(&(major, minor)) {
                m.by_dev.insert((major, minor), point);
            }
        }
        m
    }

    /// Reads /proc/self/mountinfo (empty table if unreadable).
    pub fn load() -> Mounts {
        Mounts::parse(&std::fs::read("/proc/self/mountinfo").unwrap_or_default())
    }

    /// Absolute path from a kernel dev_t and a leaf-first NUL-separated walk.
    pub fn walk_to_path(&self, kdev: u64, walk: &[u8]) -> Vec<u8> {
        let major = ((kdev >> 20) & 0xfff) as u32;
        let minor = (kdev & 0xfffff) as u32;
        let mut comps: Vec<&[u8]> = walk.split(|&b| b == 0).filter(|c| !c.is_empty()).collect();
        comps.reverse();
        let mut out = match self.by_dev.get(&(major, minor)) {
            Some(p) if p.as_slice() != b"/" => p.clone(),
            _ => Vec::new(),
        };
        for c in comps {
            out.push(b'/');
            out.extend_from_slice(c);
        }
        if out.is_empty() {
            out.push(b'/');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"22 1 254:1 / / rw,relatime shared:1 - ext4 /dev/mapper/root rw\n\
30 22 0:44 / /tmp rw shared:2 - tmpfs tmpfs rw\n\
31 22 254:1 /srv/data /mnt/my\\040data rw - ext4 /dev/mapper/root rw\n\
32 22 0:50 /sub /bind rw - tmpfs t rw\n\
garbage line\n";

    #[test]
    fn prefixes_mount_point_and_reverses_walk() {
        let m = Mounts::parse(SAMPLE);
        let tmp = 44u64; // 0:44
        assert_eq!(
            m.walk_to_path(tmp, b"f.txt\0dir\0"),
            b"/tmp/dir/f.txt".to_vec()
        );
        let root = (254u64 << 20) | 1;
        assert_eq!(
            m.walk_to_path(root, b"passwd\0etc\0"),
            b"/etc/passwd".to_vec()
        );
        // Unknown device: path relative to the filesystem root.
        assert_eq!(m.walk_to_path(99, b"x\0"), b"/x".to_vec());
        // Only a non-root bind mount known: used as best effort.
        assert_eq!(m.walk_to_path(50, b"x\0"), b"/bind/x".to_vec());
    }

    #[test]
    fn octal_escapes_are_decoded() {
        assert_eq!(
            unescape_octal(b"/mnt/my\\040data"),
            b"/mnt/my data".to_vec()
        );
        assert_eq!(unescape_octal(b"a\\9b"), b"a\\9b".to_vec());
    }
}
