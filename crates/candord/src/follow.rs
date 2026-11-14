//! Follow mode (D9, WP09): trace one process tree only, enforced in the kernel.
//!
//! `start` puts the root's tgid into `followed_tgid`; from then on the fork
//! program adds every new child at fork time. Processes that already existed
//! are found by scanning /proc for descendants, repeated until two scans in a
//! row add nothing. Only then is `cfg.mode` switched to follow, so no part of
//! the tree is missed while switching.

use crate::abi::skel::CandorSkel;
use crate::abi::{self, Cfg};
use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags};
use std::collections::{BTreeMap, BTreeSet};
use candor_proto::ProcKey;

/// Parent pid from the text of /proc/<pid>/stat (field 4, after the last ')').
pub fn ppid_from_stat(stat: &[u8]) -> Option<u32> {
    let close = stat.iter().rposition(|&b| b == b')')?;
    let rest = std::str::from_utf8(stat.get(close + 1..)?).ok()?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Start time in clock ticks (field 22) from the text of /proc/<pid>/stat.
pub fn start_from_stat(stat: &[u8]) -> Option<u64> {
    let close = stat.iter().rposition(|&b| b == b')')?;
    let rest = std::str::from_utf8(stat.get(close + 1..)?).ok()?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Start ticks of a running pid, if readable.
pub fn start_of(pid: u32) -> Option<u64> {
    start_from_stat(&std::fs::read(format!("/proc/{pid}/stat")).ok()?)
}

/// (pid, ppid) of every process in /proc that could be read.
pub fn proc_parents() -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in dir.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        // Processes vanish while we scan; skip those silently.
        if let Ok(stat) = std::fs::read(format!("/proc/{pid}/stat"))
            && let Some(ppid) = ppid_from_stat(&stat)
        {
            out.push((pid, ppid));
        }
    }
    out
}

/// `root` and all its descendants in a (pid, ppid) list.
pub fn descendants(root: u32, parents: &[(u32, u32)]) -> BTreeSet<u32> {
    let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (pid, ppid) in parents {
        children.entry(*ppid).or_default().push(*pid);
    }
    let mut out = BTreeSet::from([root]);
    let mut todo = vec![root];
    while let Some(p) = todo.pop() {
        for c in children.get(&p).into_iter().flatten() {
            if out.insert(*c) {
                todo.push(*c);
            }
        }
    }
    out
}

/// /proc rescans when starting to follow (bounded: the kernel's fork
/// inheritance covers everything created after the root was inserted).
const MAX_SCANS: usize = 20;

fn follow_value(start_ticks: u64) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[..4].copy_from_slice(&1u32.to_le_bytes());
    v[8..].copy_from_slice(&start_ticks.to_le_bytes());
    v
}

/// Removes every entry from `followed_tgid`.
pub fn clear(skel: &CandorSkel) {
    let keys: Vec<Vec<u8>> = skel.maps.followed_tgid.keys().collect();
    for k in keys {
        let _ = skel.maps.followed_tgid.delete(&k);
    }
}

/// Follows the tree rooted at `root` (refused if that pid now belongs to
/// another process); `cfg` is the current configuration. On error the
/// followed set is cleared and the caller must stay system-wide.
pub fn start(skel: &CandorSkel, root: ProcKey, cfg: Cfg) -> Result<usize> {
    clear(skel);
    if start_of(root.tgid) != Some(root.start_ticks) {
        anyhow::bail!("process {} is gone (pid reused or exited)", root.tgid);
    }
    let insert = |pid: u32, start: u64| {
        skel.maps
            .followed_tgid
            .update(&pid.to_le_bytes(), &follow_value(start), MapFlags::ANY)
            .context("adding to followed_tgid")
    };
    insert(root.tgid, root.start_ticks)?;
    let mut known: BTreeSet<u32> = BTreeSet::from([root.tgid]);
    let mut quiet_scans = 0;
    for _ in 0..MAX_SCANS {
        let found = descendants(root.tgid, &proc_parents());
        let new: Vec<u32> = found.difference(&known).copied().collect();
        for pid in &new {
            // A descendant starts after its ancestor; anything else is a
            // recycled pid that is not part of the tree.
            if let Some(start) = start_of(*pid)
                && start >= root.start_ticks
            {
                insert(*pid, start)?;
            }
        }
        known.extend(new.iter().copied());
        quiet_scans = if new.is_empty() { quiet_scans + 1 } else { 0 };
        if quiet_scans >= 2 {
            break;
        }
    }
    let follow_cfg = Cfg {
        mode: abi::MODE_FOLLOW,
        ..cfg
    };
    skel.maps
        .cfg
        .update(&0u32.to_le_bytes(), &follow_cfg.to_bytes(), MapFlags::ANY)
        .context("switching cfg to follow mode")?;
    Ok(known.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppid_parsing_survives_hostile_comm() {
        assert_eq!(ppid_from_stat(b"42 (a) b) c) S 7 42 42 0"), Some(7));
        assert_eq!(ppid_from_stat(b"42 (x y) R 1 2"), Some(1));
        assert_eq!(ppid_from_stat(b"garbage"), None);
    }

    #[test]
    fn start_time_parsing() {
        let stat = b"42 (a) b) S 7 42 42 0 -1 4194560 1 2 3 4 5 6 7 8 20 0 1 0 98765 1 2";
        assert_eq!(start_from_stat(stat), Some(98765));
        assert_eq!(follow_value(98765)[8..], 98765u64.to_le_bytes());
    }

    #[test]
    fn descendants_follow_every_generation() {
        let p = [(2, 1), (3, 2), (4, 3), (5, 1), (6, 4)];
        assert_eq!(descendants(2, &p), BTreeSet::from([2, 3, 4, 6]));
        assert_eq!(descendants(9, &p), BTreeSet::from([9]));
    }
}
