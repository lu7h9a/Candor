//! Kernel ABI: the BPF skeleton and decoding of ring-buffer records.
//!
//! This is the only module in the project allowed to contain `unsafe`
//! (invariant I14): the libbpf-cargo generated skeleton is included here.
//! Decoding itself is safe Rust: every record is a byte slice whose length is
//! checked before any field is read, and fields are read with
//! `from_le_bytes`. The struct layouts mirror `bpf/sysscope.h`; the const
//! assertions below fail the build if the two sides ever disagree in size.
#![allow(unsafe_code)]

/// Generated BPF skeleton (`SysscopeSkel`, maps, programs).
#[allow(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs,
    dead_code
)]
pub mod skel {
    include!(concat!(env!("OUT_DIR"), "/sysscope.skel.rs"));
}

/// Maximum path bytes in one event (PATH_CAP in sysscope.h).
pub const PATH_CAP: usize = 512;
/// Maximum argv bytes in one event (ARGV_CAP in sysscope.h).
pub const ARGV_CAP: usize = 256;

/// Event kind numbers (EV_* in sysscope.h).
pub const EV_EXEC: u16 = 1;
/// FORK kind.
pub const EV_FORK: u16 = 2;
/// EXIT kind.
pub const EV_EXIT: u16 = 3;

/// Header flag: path was cut or only the leaf is present.
#[allow(dead_code)] // used by file events (WP06)
pub const F_PATH_TRUNCATED: u16 = 1 << 0;
/// Header flag: argv was cut at ARGV_CAP.
pub const F_ARGV_TRUNCATED: u16 = 1 << 1;
/// Header flag: executable had no link on disk.
pub const F_FILELESS: u16 = 1 << 2;
/// Header flag: kernel thread.
#[allow(dead_code)] // used by the process table (WP11)
pub const F_KTHREAD: u16 = 1 << 3;
/// Header flag: exec path is the execve() argument, not kernel-resolved.
#[allow(dead_code)] // used by the process table (WP11)
pub const F_PATH_FROM_ARG: u16 = 1 << 4;

/// Index of each reason in the `drops` map (DROP_* in sysscope.h).
pub const DROP_RINGBUF: u32 = 0;
/// Budget drop index.
pub const DROP_BUDGET: u32 = 1;
/// Scratch drop index.
pub const DROP_SCRATCH: u32 = 2;

/// Mirror of `struct cfg`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cfg {
    /// 0 system-wide, 1 follow-only.
    pub mode: u32,
    /// Events per second per tgid.
    pub budget_rate: u32,
    /// Bucket size.
    pub budget_burst: u32,
    /// Reserved.
    pub flags: u32,
}

impl Cfg {
    /// Bytes as the kernel expects them in the `cfg` map.
    pub fn to_bytes(self) -> [u8; 16] {
        let words = [self.mode, self.budget_rate, self.budget_burst, self.flags];
        let mut b = [0u8; 16];
        for (chunk, w) in b.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            *chunk = w.to_le_bytes();
        }
        b
    }
}

// Layout mirrors, used only for the size assertions below.
#[repr(C)]
struct EvHdrLayout {
    ts_boot_ns: u64,
    start_boot_ns: u64,
    tgid: u32,
    pid: u32,
    uid: u32,
    kind: u16,
    flags: u16,
}
#[repr(C)]
struct EvExecLayout {
    h: EvHdrLayout,
    dev: u64,
    ino: u64,
    parent_start_boot_ns: u64,
    parent_tgid: u32,
    path_len: u16,
    argv_len: u16,
    path: [u8; PATH_CAP],
    argv: [u8; ARGV_CAP],
}
#[repr(C)]
struct EvForkLayout {
    h: EvHdrLayout,
    child_start_boot_ns: u64,
    child_tgid: u32,
    pad: u32,
}
#[repr(C)]
struct EvExitLayout {
    h: EvHdrLayout,
    exit_code: i32,
    pad: u32,
}

/// Size of `struct ev_hdr`.
pub const HDR_SIZE: usize = 32;
/// Size of `struct ev_exec`.
pub const EXEC_SIZE: usize = 64 + PATH_CAP + ARGV_CAP;
/// Size of `struct ev_fork`.
pub const FORK_SIZE: usize = 48;
/// Size of `struct ev_exit`.
pub const EXIT_SIZE: usize = 40;

const _: () = assert!(std::mem::size_of::<EvHdrLayout>() == HDR_SIZE);
const _: () = assert!(std::mem::size_of::<EvExecLayout>() == EXEC_SIZE);
const _: () = assert!(std::mem::size_of::<EvForkLayout>() == FORK_SIZE);
const _: () = assert!(std::mem::size_of::<EvExitLayout>() == EXIT_SIZE);
const _: () = assert!(std::mem::size_of::<Cfg>() == 16);

/// Common header of every kernel record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hdr {
    /// CLOCK_BOOTTIME ns of the event.
    pub ts_boot_ns: u64,
    /// Start time of the process (group leader) in boot ns.
    pub start_boot_ns: u64,
    /// Thread-group id.
    pub tgid: u32,
    /// Thread id.
    pub pid: u32,
    /// User id.
    pub uid: u32,
    /// EV_* kind.
    pub kind: u16,
    /// F_* flags.
    pub flags: u16,
}

/// A decoded kernel record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawEvent {
    /// Program executed.
    Exec {
        /// Header.
        h: Hdr,
        /// Kernel dev_t of the executable.
        dev: u64,
        /// Inode of the executable.
        ino: u64,
        /// Parent tgid.
        parent_tgid: u32,
        /// Parent start time (boot ns).
        parent_start_boot_ns: u64,
        /// Path bytes (no NUL).
        path: Vec<u8>,
        /// Argument bytes, NUL separated.
        argv: Vec<u8>,
    },
    /// New child process.
    Fork {
        /// Header (the parent).
        h: Hdr,
        /// Child tgid.
        child_tgid: u32,
        /// Child start time (boot ns).
        child_start_boot_ns: u64,
    },
    /// Process gone.
    Exit {
        /// Header.
        h: Hdr,
        /// Raw exit code.
        exit_code: i32,
    },
}

/// Why a record could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AbiError {
    /// Record shorter than its kind requires.
    #[error("record of kind {kind} is {len} bytes, expected at least {need}")]
    Short {
        /// Kind number.
        kind: u16,
        /// Actual length.
        len: usize,
        /// Required length.
        need: usize,
    },
    /// Unknown kind number.
    #[error("unknown record kind {0}")]
    UnknownKind(u16),
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    let mut a = [0u8; 2];
    if let Some(s) = b.get(off..off + 2) {
        a.copy_from_slice(s);
    }
    u16::from_le_bytes(a)
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    let mut a = [0u8; 4];
    if let Some(s) = b.get(off..off + 4) {
        a.copy_from_slice(s);
    }
    u32::from_le_bytes(a)
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    if let Some(s) = b.get(off..off + 8) {
        a.copy_from_slice(s);
    }
    u64::from_le_bytes(a)
}

/// Bytes `[off, off+len)` of `b`, with `len` clamped to `cap` and to the slice.
fn bytes_at(b: &[u8], off: usize, len: usize, cap: usize) -> Vec<u8> {
    let len = len.min(cap);
    b.get(off..off + len)
        .map(|s| s.to_vec())
        .unwrap_or_default()
}

fn need(b: &[u8], kind: u16, n: usize) -> Result<(), AbiError> {
    if b.len() < n {
        return Err(AbiError::Short {
            kind,
            len: b.len(),
            need: n,
        });
    }
    Ok(())
}

/// Decodes one ring-buffer record. Never panics, whatever the input.
pub fn decode(b: &[u8]) -> Result<RawEvent, AbiError> {
    need(b, 0, HDR_SIZE)?;
    let h = Hdr {
        ts_boot_ns: u64_at(b, 0),
        start_boot_ns: u64_at(b, 8),
        tgid: u32_at(b, 16),
        pid: u32_at(b, 20),
        uid: u32_at(b, 24),
        kind: u16_at(b, 28),
        flags: u16_at(b, 30),
    };
    match h.kind {
        EV_EXEC => {
            need(b, h.kind, EXEC_SIZE)?;
            let path_len = usize::from(u16_at(b, 60));
            let argv_len = usize::from(u16_at(b, 62));
            Ok(RawEvent::Exec {
                h,
                dev: u64_at(b, 32),
                ino: u64_at(b, 40),
                parent_start_boot_ns: u64_at(b, 48),
                parent_tgid: u32_at(b, 56),
                path: bytes_at(b, 64, path_len, PATH_CAP),
                argv: bytes_at(b, 64 + PATH_CAP, argv_len, ARGV_CAP),
            })
        }
        EV_FORK => {
            need(b, h.kind, FORK_SIZE)?;
            Ok(RawEvent::Fork {
                h,
                child_start_boot_ns: u64_at(b, 32),
                child_tgid: u32_at(b, 40),
            })
        }
        EV_EXIT => {
            need(b, h.kind, EXIT_SIZE)?;
            Ok(RawEvent::Exit {
                h,
                exit_code: u32_at(b, 32) as i32,
            })
        }
        k => Err(AbiError::UnknownKind(k)),
    }
}

/// Converts a kernel `dev_t` (major << 20 | minor) to the userspace encoding
/// that `stat(2)` returns in `st_dev` (glibc `makedev`).
pub fn kernel_dev_to_user(kdev: u64) -> u64 {
    let major = (kdev >> 20) & 0xfff;
    let minor = kdev & 0xfffff;
    ((major & 0xfffff000) << 32)
        | ((major & 0xfff) << 8)
        | ((minor & 0xffffff00) << 12)
        | (minor & 0xff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr_bytes(kind: u16, flags: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&111u64.to_le_bytes());
        b.extend_from_slice(&222u64.to_le_bytes());
        b.extend_from_slice(&10u32.to_le_bytes());
        b.extend_from_slice(&11u32.to_le_bytes());
        b.extend_from_slice(&1000u32.to_le_bytes());
        b.extend_from_slice(&kind.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        b
    }

    #[test]
    fn decodes_fork_and_exit() {
        let mut b = hdr_bytes(EV_FORK, 0);
        b.extend_from_slice(&333u64.to_le_bytes());
        b.extend_from_slice(&12u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        let e = decode(&b).unwrap();
        assert!(matches!(
            e,
            RawEvent::Fork {
                child_tgid: 12,
                child_start_boot_ns: 333,
                ..
            }
        ));

        let mut b = hdr_bytes(EV_EXIT, F_KTHREAD);
        b.extend_from_slice(&(-9i32).to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        match decode(&b).unwrap() {
            RawEvent::Exit { h, exit_code } => {
                assert_eq!(exit_code, -9);
                assert_eq!(h.flags, F_KTHREAD);
                assert_eq!(h.tgid, 10);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn exec_lengths_are_clamped_to_caps() {
        let mut b = hdr_bytes(EV_EXEC, 0);
        b.extend_from_slice(&1u64.to_le_bytes());
        b.extend_from_slice(&2u64.to_le_bytes());
        b.extend_from_slice(&3u64.to_le_bytes());
        b.extend_from_slice(&4u32.to_le_bytes());
        b.extend_from_slice(&u16::MAX.to_le_bytes()); // hostile path_len
        b.extend_from_slice(&3u16.to_le_bytes());
        b.resize(EXEC_SIZE, b'a');
        match decode(&b).unwrap() {
            RawEvent::Exec { path, argv, .. } => {
                assert_eq!(path.len(), PATH_CAP);
                assert_eq!(argv.len(), 3);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn short_and_unknown_records_are_errors() {
        assert!(decode(&[0u8; 5]).is_err());
        let b = hdr_bytes(EV_EXEC, 0);
        assert!(matches!(decode(&b), Err(AbiError::Short { .. })));
        let b = hdr_bytes(99, 0);
        assert_eq!(decode(&b), Err(AbiError::UnknownKind(99)));
    }

    #[test]
    fn dev_conversion_matches_glibc_makedev() {
        // 8:2 (sda2) and 259:65537 (large minor).
        assert_eq!(kernel_dev_to_user((8 << 20) | 2), 0x802);
        let k = (259u64 << 20) | 65537;
        // glibc: ((minor & 0xffffff00) << 12) | ((major & 0xfff) << 8) | (minor & 0xff)
        assert_eq!(
            kernel_dev_to_user(k),
            ((65537 & 0xffffff00) << 12) | (259 << 8) | 1
        );
    }
}

#[cfg(test)]
mod invariant_tests {
    /// I2: BPF programs only observe. None of the helpers that change kernel
    /// or process behaviour may be called anywhere in the BPF sources.
    #[test]
    fn bpf_sources_call_no_forbidden_helpers() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bpf");
        let forbidden = [
            "bpf_probe_write_user(",
            "bpf_override_return(",
            "bpf_send_signal(",
            "bpf_send_signal_thread(",
        ];
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() {
                continue; // skips bpf/vmlinux/
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for f in forbidden {
                assert!(!text.contains(f), "{} calls {f}", path.display());
            }
            checked += 1;
        }
        assert!(
            checked >= 5,
            "expected the BPF sources in {}",
            dir.display()
        );
    }
}
