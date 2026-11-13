//! Syscall statistics read from the kernel maps (D8, WP08).
//!
//! The BPF side only counts; this module sums the per-CPU counters, turns
//! numbers into names (table generated at build time from unistd_64.h) and
//! reads the latency map that is filled for followed processes.

use crate::abi::skel::SysscopeSkel;
use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags};
use std::collections::BTreeMap;
use sysscope_proto::ProcKey;

include!(concat!(env!("OUT_DIR"), "/syscall_names.rs"));

/// Name of a syscall number ("sys_<nr>" if unknown).
pub fn name(nr: u32) -> String {
    SYSCALL_NAMES
        .iter()
        .find(|(n, _)| *n == nr)
        .map(|(_, s)| s.to_string())
        .unwrap_or_else(|| format!("sys_{nr}"))
}

/// Counters for one (tgid, syscall).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SysTotals {
    /// Calls counted.
    pub count: u64,
    /// Latency samples.
    pub lat_count: u64,
    /// Total latency ns.
    pub lat_total_ns: u64,
    /// Max latency ns.
    pub lat_max_ns: u64,
}

fn key_parts(k: &[u8]) -> Option<(ProcKey, u32)> {
    let tgid = u32::from_le_bytes(k.get(0..4)?.try_into().ok()?);
    let nr = u32::from_le_bytes(k.get(4..8)?.try_into().ok()?);
    let start_ticks = u64::from_le_bytes(k.get(8..16)?.try_into().ok()?);
    Some((ProcKey { tgid, start_ticks }, nr))
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    b.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

/// Reads every (tgid, nr) counter and latency entry.
pub fn read_all(skel: &SysscopeSkel) -> Result<BTreeMap<(ProcKey, u32), SysTotals>> {
    let mut out: BTreeMap<(ProcKey, u32), SysTotals> = BTreeMap::new();
    for k in skel.maps.sys_count.keys() {
        let Some(id) = key_parts(&k) else { continue };
        let per_cpu = skel
            .maps
            .sys_count
            .lookup_percpu(&k, MapFlags::ANY)
            .context("reading sys_count")?
            .unwrap_or_default();
        let sum = per_cpu
            .iter()
            .map(|v| u64_at(v, 0))
            .fold(0u64, u64::saturating_add);
        out.entry(id).or_default().count = sum;
    }
    for k in skel.maps.sys_lat.keys() {
        let Some(id) = key_parts(&k) else { continue };
        if let Some(v) = skel
            .maps
            .sys_lat
            .lookup(&k, MapFlags::ANY)
            .context("reading sys_lat")?
        {
            let t = out.entry(id).or_default();
            t.lat_count = u64_at(&v, 0);
            t.lat_total_ns = u64_at(&v, 8);
            t.lat_max_ns = u64_at(&v, 16);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_come_from_the_generated_table() {
        assert!(SYSCALL_NAMES.len() > 300);
        assert_eq!(name(0), "read");
        assert_eq!(name(110), "getppid");
        assert_eq!(name(99_999), "sys_99999");
    }
}
