//! Retention limits of the core state (plan section 4.6).
//!
//! Every collection the core keeps has a fixed cap defined here (invariant
//! I8), and each cap has a test that hits it. Changing a number in this file
//! needs a "Deviations from the plan" entry in PROGRESS.md
//! (scripts/check-integrity.sh enforces that).

/// Live (not exited) processes tracked.
pub const MAX_LIVE_PROCS: usize = 8192;
/// Exited processes kept for display, oldest evicted first.
pub const MAX_EXITED_PROCS: usize = 2048;
/// How long an exited process is kept (ns).
pub const EXITED_RETENTION_NS: u64 = 600 * 1_000_000_000;
/// Recent events kept per process.
pub const PER_PROC_RECENT_EVENTS: usize = 2000;
/// Events kept in the global ring.
pub const GLOBAL_EVENTS: usize = 100_000;
/// CPU/memory samples kept per process (1 Hz, one hour).
pub const SERIES_POINTS: usize = 3600;
/// Findings kept.
pub const MAX_FINDINGS: usize = 5000;
/// Distinct files kept per process; more are counted as "other".
pub const PER_PROC_FILES: usize = 5000;
/// Distinct connection destinations kept per process; more are "other".
pub const PER_PROC_CONNS: usize = 2000;
/// Distinct syscall numbers kept per process.
pub const PER_PROC_SYSCALLS: usize = 1024;
/// A live process missing from this many consecutive full /proc scans is
/// treated as exited (its EXIT event may have been lost).
pub const MISSED_SCANS_TO_EXIT: u32 = 2;
/// Clock ticks per second used by /proc (USER_HZ).
pub const CLK_TCK: u64 = 100;
