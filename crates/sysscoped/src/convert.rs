//! Turns decoded kernel records (`abi::RawEvent`) into protocol events.
//!
//! This is where kernel encodings become user-facing ones: boot-time start
//! nanoseconds become `ProcKey.start_ticks` (clock ticks, plan 4.4) and the
//! kernel `dev_t` becomes the `st_dev` encoding that `stat(2)` reports.

use crate::abi::{self, RawEvent};
use sysscope_proto::{BStr, Event, EventKind, ProcKey};

/// USER_HZ: clock ticks per second used by /proc/<pid>/stat. It is 100 on
/// every x86_64 Linux kernel (WP10 verifies the resulting keys against /proc).
pub const CLK_TCK: u64 = 100;

/// Converts a boot-time start in ns to /proc start ticks.
pub fn start_ticks(start_boot_ns: u64) -> u64 {
    start_boot_ns / (1_000_000_000 / CLK_TCK)
}

fn key(tgid: u32, start_boot_ns: u64) -> ProcKey {
    ProcKey {
        tgid,
        start_ticks: start_ticks(start_boot_ns),
    }
}

/// Builds a protocol event with the given id from a kernel record.
pub fn to_event(id: u64, raw: &RawEvent) -> Event {
    let (h, kind) = match raw {
        RawEvent::Exec {
            h,
            dev,
            ino,
            path,
            argv,
            ..
        } => (
            h,
            EventKind::Exec {
                exe: BStr(path.clone()),
                argv: BStr(argv.clone()),
                argv_trunc: h.flags & abi::F_ARGV_TRUNCATED != 0,
                fileless: h.flags & abi::F_FILELESS != 0,
                dev: abi::kernel_dev_to_user(*dev),
                ino: *ino,
            },
        ),
        RawEvent::Fork {
            h,
            child_tgid,
            child_start_boot_ns,
        } => (
            h,
            EventKind::Fork {
                child: key(*child_tgid, *child_start_boot_ns),
            },
        ),
        RawEvent::Exit { h, .. } => (h, EventKind::Exit {}),
    };
    Event {
        id,
        ts_ns: h.ts_boot_ns,
        proc: key(h.tgid, h.start_boot_ns),
        tid: h.pid,
        uid: h.uid,
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_ticks_divides_by_ten_million() {
        assert_eq!(start_ticks(0), 0);
        assert_eq!(start_ticks(9_999_999), 0);
        assert_eq!(start_ticks(10_000_000), 1);
        assert_eq!(start_ticks(123_456_789_000), 12_345);
    }
}
