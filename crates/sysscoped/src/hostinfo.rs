//! Facts about executables and users that the detector needs (plan 5.3):
//! whether an executable is root-owned and not group/world-writable (the
//! allowlist condition), whether it lives in a system directory, whether its
//! directory is world-writable (R002), and each uid's home directory.
//!
//! The executable is inspected through /proc/<pid>/exe, the kernel's own
//! link to the running file, never through a path a client supplied (I12).

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use sysscope_proto::{BStr, ProcKey};

/// Home directories by uid, from /etc/passwd (read at start and on SIGHUP).
pub fn load_homes() -> BTreeMap<u32, Vec<u8>> {
    let text = std::fs::read("/etc/passwd").unwrap_or_default();
    let mut out = BTreeMap::new();
    for line in text.split(|&b| b == b'\n') {
        let f: Vec<&[u8]> = line.split(|&b| b == b':').collect();
        if let (Some(uid), Some(home)) = (f.get(2), f.get(5))
            && let Some(uid) = std::str::from_utf8(uid).ok().and_then(|u| u.parse().ok())
        {
            out.insert(uid, home.to_vec());
        }
    }
    out
}

/// Modification time of /etc/passwd (None if it cannot be read).
pub fn passwd_mtime() -> Option<std::time::SystemTime> {
    std::fs::metadata("/etc/passwd")
        .and_then(|m| m.modified())
        .ok()
}

const SYSTEM_DIRS: &[&[u8]] = &[
    b"/usr/bin/",
    b"/usr/sbin/",
    b"/usr/lib/",
    b"/usr/libexec/",
    b"/bin/",
    b"/sbin/",
    b"/lib/",
    b"/opt/",
];

/// (trusted, system_dir, world_writable_dir) for a running process.
/// `current_start` is the start time /proc reports now for that pid: if it
/// is not the process's own (pid reused, or gone), nothing is trusted.
pub fn exe_facts(key: ProcKey, exe: &BStr, current_start: Option<u64>) -> (bool, bool, bool) {
    if current_start != Some(key.start_ticks) {
        return (false, false, false);
    }
    let link = format!("/proc/{}/exe", key.tgid);
    // Following the magic link reaches the file the process really runs.
    let file_ok = std::fs::metadata(&link)
        .map(|m| m.uid() == 0 && m.mode() & 0o022 == 0 && m.is_file())
        .unwrap_or(false);
    let bytes = exe.as_bytes();
    let dir = match bytes.iter().rposition(|&b| b == b'/') {
        Some(0) => b"/".as_slice(),
        Some(i) => bytes.get(..i).unwrap_or(b""),
        None => b"".as_slice(),
    };
    // The path is the process's own view (its mount namespace and root):
    // look the directory up through /proc/<pid>/root, so a bind mount or
    // chroot that makes "~/evil" appear as "/usr/bin/evil" is checked as
    // what it really is (review 2 finding 5, I5). A d_path result has no
    // symlink components, so nothing can escape that root.
    let dir_meta = if dir.is_empty() {
        None
    } else {
        let mut p = format!("/proc/{}/root", key.tgid).into_bytes();
        p.extend_from_slice(dir);
        std::fs::metadata(std::ffi::OsStr::from_bytes(&p)).ok()
    };
    let dir_ok = dir_meta
        .as_ref()
        .map(|m| m.uid() == 0 && m.mode() & 0o022 == 0)
        .unwrap_or(false);
    let world_writable = dir_meta.map(|m| m.mode() & 0o002 != 0).unwrap_or(false);
    let trusted = file_ok && dir_ok;
    let system = trusted && SYSTEM_DIRS.iter().any(|d| bytes.starts_with(d));
    (trusted, system, world_writable)
}

/// True if `exe` (the path as the process sees it) does not name the file
/// the process runs when looked up in the host's view (pid 1's root): a
/// private mount namespace or chroot (owner's Q7 answer A). Hardened
/// services in their own namespace see the same files and are not marked.
/// Deleted and memfd executables are R003's case, relative fallback paths
/// cannot be judged: both false.
pub fn private_view(key: ProcKey, exe: &BStr, current_start: Option<u64>) -> bool {
    if current_start != Some(key.start_ticks) || exe.as_bytes().first() != Some(&b'/') {
        return false;
    }
    let Ok(real) = std::fs::metadata(format!("/proc/{}/exe", key.tgid)) else {
        return false;
    };
    if real.nlink() == 0 {
        return false;
    }
    let mut p = b"/proc/1/root".to_vec();
    p.extend_from_slice(exe.as_bytes());
    match std::fs::metadata(std::ffi::OsStr::from_bytes(&p)) {
        Ok(h) => (h.dev(), h.ino()) != (real.dev(), real.ino()),
        Err(_) => true,
    }
}

/// True if the process shares the host's mount namespace (pid 1's).
pub fn in_host_mount_ns(tgid: u32) -> bool {
    let ns = |p: String| std::fs::metadata(p).map(|m| (m.dev(), m.ino())).ok();
    match (
        ns(format!("/proc/{tgid}/ns/mnt")),
        ns("/proc/1/ns/mnt".into()),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// True if a script file is root-owned, not group/world-writable and a
/// regular file, and so is its directory (the allowlist check of plan 5.3
/// applied to an interpreter's script). Symlinks are resolved first, in the
/// host's view, so only processes in the host's mount namespace qualify: in
/// another namespace the same path (or an absolute symlink) can name a
/// different file (review 2 finding 5).
pub fn script_trusted(tgid: u32, path: &BStr) -> bool {
    let bytes = path.as_bytes();
    if bytes.first() != Some(&b'/') {
        return false; // relative to an unknown cwd: never trusted
    }
    if !in_host_mount_ns(tgid) {
        return false;
    }
    let Ok(real) = std::fs::canonicalize(std::ffi::OsStr::from_bytes(bytes)) else {
        return false;
    };
    let ok = |p: &std::path::Path, file: bool| {
        std::fs::metadata(p)
            .map(|m| m.uid() == 0 && m.mode() & 0o022 == 0 && (!file || m.is_file()))
            .unwrap_or(false)
    };
    ok(&real, true) && real.parent().is_some_and(|d| ok(d, false))
}

/// /proc/<pid>/maps of a process, if its start time still matches the key
/// (so a recycled pid is never read). At most `cap` rows.
pub fn read_maps(key: ProcKey, cap: usize) -> Option<Vec<sysscope_proto::MapRow>> {
    let stat = std::fs::read(format!("/proc/{}/stat", key.tgid)).ok()?;
    let close = stat.iter().rposition(|&b| b == b')')?;
    let start: u64 = std::str::from_utf8(stat.get(close + 2..)?)
        .ok()?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()?;
    if start != key.start_ticks {
        return None;
    }
    let text = std::fs::read(format!("/proc/{}/maps", key.tgid)).ok()?;
    let mut rows = Vec::new();
    for line in text
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .take(cap)
    {
        let f: Vec<&[u8]> = line.splitn(6, |&b| b == b' ').collect();
        let s = |i: usize| {
            f.get(i)
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default()
        };
        let range = s(0);
        let (a, b) = range.split_once('-').unwrap_or(("0", "0"));
        rows.push(sysscope_proto::MapRow {
            start: u64::from_str_radix(a, 16).unwrap_or(0),
            end: u64::from_str_radix(b, 16).unwrap_or(0),
            perms: s(1),
            offset: u64::from_str_radix(&s(2), 16).unwrap_or(0),
            dev: s(3),
            inode: s(4).parse().unwrap_or(0),
            path: BStr(
                f.get(5)
                    .map(|p| p.trim_ascii_start().to_vec())
                    .unwrap_or_default(),
            ),
        });
    }
    Some(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_process_facts_and_maps() {
        let me = std::process::id();
        let homes = load_homes();
        assert!(homes.contains_key(&0));
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let start: u64 = stat
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap()
            .parse()
            .unwrap();
        let key = ProcKey {
            tgid: me,
            start_ticks: start,
        };
        let maps = read_maps(key, 5000).unwrap();
        assert!(!maps.is_empty());
        // Wrong start time: refused (pid reuse protection).
        assert!(
            read_maps(
                ProcKey {
                    tgid: me,
                    start_ticks: start + 1
                },
                10
            )
            .is_none()
        );
        // A test binary under target/ is not root-owned: untrusted.
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        let exe = BStr(exe.into_os_string().into_encoded_bytes());
        let (trusted, system, _) = exe_facts(key, &exe, Some(start));
        assert!(!trusted && !system);
        // Root-owned /proc/self/exe of a pid reused by another process: refused.
        assert_eq!(exe_facts(key, &exe, Some(start + 1)), (false, false, false));
    }
}
