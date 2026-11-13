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
    let dir_meta = if dir.is_empty() {
        None
    } else {
        std::fs::metadata(std::ffi::OsStr::from_bytes(dir)).ok()
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

/// True if a script file is root-owned, not group/world-writable and a
/// regular file, and so is its directory (the allowlist check of plan 5.3
/// applied to an interpreter's script). Symlinks are resolved first.
pub fn script_trusted(path: &BStr) -> bool {
    let bytes = path.as_bytes();
    if bytes.first() != Some(&b'/') {
        return false; // relative to an unknown cwd: never trusted
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
