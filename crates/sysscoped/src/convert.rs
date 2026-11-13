//! Turns decoded kernel records (`abi::RawEvent`) into protocol events.
//!
//! This is where kernel encodings become user-facing ones: boot-time start
//! nanoseconds become `ProcKey.start_ticks` (clock ticks, plan 4.4) and the
//! kernel `dev_t` becomes the `st_dev` encoding that `stat(2)` reports.

use crate::abi::{self, RawEvent};
use crate::mounts::Mounts;
use crate::sockaddr;
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

const FMODE_READ: u32 = 0x1;
const FMODE_WRITE: u32 = 0x2;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;

/// Builds a protocol event with the given id from a kernel record.
pub fn to_event(id: u64, raw: &RawEvent, mounts: &Mounts) -> Event {
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
        RawEvent::Connect { h, sock_type, addr } => {
            let (family, text, port) = sockaddr::parse(addr);
            (
                h,
                EventKind::Connect {
                    family,
                    addr: text,
                    port,
                    sock: sockaddr::sock_type(*sock_type),
                },
            )
        }
        RawEvent::Listen {
            h,
            family,
            port,
            addr,
        } => {
            let (_, text) = sockaddr::listen_addr(*family, addr);
            (
                h,
                EventKind::Listen {
                    addr: text,
                    port: *port,
                },
            )
        }
        RawEvent::Open {
            h,
            dev,
            ino,
            f_flags,
            f_mode,
            path,
        } => (
            h,
            EventKind::Open {
                path: BStr(path.clone()),
                dev: abi::kernel_dev_to_user(*dev),
                ino: *ino,
                read: f_mode & FMODE_READ != 0,
                write: f_mode & FMODE_WRITE != 0,
                create: f_flags & O_CREAT != 0,
                trunc: f_flags & O_TRUNC != 0,
                path_trunc: h.flags & abi::F_PATH_TRUNCATED != 0,
            },
        ),
        RawEvent::Rename {
            h,
            dev,
            ino,
            old_walk,
            new_walk,
        } => (
            h,
            EventKind::Rename {
                old: BStr(mounts.walk_to_path_flagged(
                    *dev,
                    old_walk,
                    h.flags & abi::F_PATH_TRUNCATED != 0,
                )),
                new: BStr(mounts.walk_to_path_flagged(
                    *dev,
                    new_walk,
                    h.flags & abi::F_PATH_TRUNCATED != 0,
                )),
                dev: abi::kernel_dev_to_user(*dev),
                ino: *ino,
                // Rebuilt from dentries + mount table: always approximate.
                approx: true,
            },
        ),
        RawEvent::Unlink { h, dev, ino, walk } => (
            h,
            EventKind::Unlink {
                path: BStr(mounts.walk_to_path_flagged(
                    *dev,
                    walk,
                    h.flags & abi::F_PATH_TRUNCATED != 0,
                )),
                dev: abi::kernel_dev_to_user(*dev),
                ino: *ino,
                approx: true,
            },
        ),
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
