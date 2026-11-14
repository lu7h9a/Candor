//! /proc sampler (D12, WP10): CPU time, memory, threads and I/O of every
//! process, read at 1 Hz with the `procfs` crate.
//!
//! Processes appear and vanish while we read; any process whose files
//! cannot be read is skipped without error. The ProcKey uses field 22 of
//! /proc/<pid>/stat (start time in clock ticks), which matches the key the
//! BPF side derives from start_boottime (plan 4.4, checked in WP10).

use candor_core::ProcSample;
use candor_proto::{BStr, ProcKey};

const PF_KTHREAD: u32 = 0x0020_0000;

/// CLOCK_BOOTTIME now, in ns (the clock the BPF programs use).
pub fn boot_ns() -> u64 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    (t.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(t.tv_nsec as u64)
}

/// Reads one process; None if it vanished or is unreadable.
fn sample_one(p: &procfs::process::Process, page: u64) -> Option<ProcSample> {
    let stat = p.stat().ok()?;
    let statm = p.statm().ok();
    let io = p.io().ok();
    let exe = p
        .exe()
        .map(|e| e.into_os_string().into_encoded_bytes())
        .unwrap_or_default();
    Some(ProcSample {
        key: ProcKey {
            tgid: u32::try_from(stat.pid).ok()?,
            start_ticks: stat.starttime,
        },
        ppid: u32::try_from(stat.ppid).unwrap_or(0),
        exe: BStr(exe),
        comm: BStr::from(stat.comm.as_str()),
        uid: p.uid().unwrap_or(u32::MAX),
        kthread: stat.flags & PF_KTHREAD != 0,
        cpu_ticks: stat.utime.saturating_add(stat.stime),
        rss: statm.map(|m| m.resident.saturating_mul(page)).unwrap_or(0),
        threads: u32::try_from(stat.num_threads).unwrap_or(0),
        // rchar/wchar: all bytes read/written through syscalls (files,
        // pipes, sockets). Needs privilege for other users' processes.
        io_r: io.as_ref().map(|i| i.rchar).unwrap_or(0),
        io_w: io.as_ref().map(|i| i.wchar).unwrap_or(0),
    })
}

/// One full scan of /proc.
pub fn sample_all() -> Vec<ProcSample> {
    let page = procfs::page_size();
    let Ok(all) = procfs::process::all_processes() else {
        return Vec::new();
    };
    all.flatten().filter_map(|p| sample_one(&p, page)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_include_this_process_with_its_start_time() {
        let me = std::process::id();
        let all = sample_all();
        let mine = all
            .iter()
            .find(|s| s.key.tgid == me)
            .expect("self in /proc");
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let after = stat.rsplit_once(')').unwrap().1;
        let start: u64 = after.split_whitespace().nth(19).unwrap().parse().unwrap();
        assert_eq!(mine.key.start_ticks, start);
        assert!(mine.rss > 0 && mine.threads >= 1);
        assert!(boot_ns() > 0);
    }
}
